# taskdb

A fast, lockable, git-friendly task & note store for this repo. It replaces
ad-hoc markdown planning files: tasks live in a SQLite database for quick
queries and atomic session locking, and `freeze`/`thaw` bridge that database to
a directory of committable JSON so git history stays meaningful.

Full design rationale: doc 21 (taskdb design), in the project's internal design corpus.

## Setup

```sh
make taskdb          # builds .bin/taskdb (gitignored)
make install-hooks   # points git at scripts/hooks/ via core.hooksPath
```

`make install-hooks` is a **once-per-clone** step: it sets
`core.hooksPath=scripts/hooks` (local config git won't auto-apply from a fresh
clone). After that, git runs the tracked hooks directly, and any hook added to
`scripts/hooks/` later is picked up with no re-install.

`taskdb` is a standalone Go module (outside `go.work`); the Makefile builds it
with `GOWORK=off`. Every dependency is pure Go (`modernc.org/sqlite`, the MCP
SDK, bubbletea for the TUI), so there is no C toolchain and the result is a
single static binary.

The `scripts/` tree (this module included) is covered by the SPDX license
ratchet: every Go, Python, shell, and TypeScript source here carries an
`SPDX-License-Identifier: Apache-2.0` first-line header, and
`scripts/check-spdx.sh` fails closed on any new file that omits it — add the
header (for Go, the `//` comment above the package clause) when creating a
file in this module.

## Two stores, one source of truth

| store              | path             | tracked? | role                         |
|--------------------|------------------|----------|------------------------------|
| live (working)     | `taskdb.sqlite`  | no       | what every command reads/writes |
| committed (canon)  | `tasks/*.json`   | yes      | what git tracks; the source of truth |

`freeze` writes the live DB out to `tasks/*.json`; `thaw` rebuilds the live DB
from it. The `tasks/` directory does not ship — it is created by the first
`freeze`, so a fresh clone has no canon until one runs. The git hooks run these
for you:

- **pre-commit** → `freeze` + stage `tasks/`, so each commit carries current state
- **post-checkout / post-merge / post-rewrite** → `thaw`, so the live DB matches the branch you land on

The hooks no-op silently if `.bin/taskdb` isn't built, so a fresh clone commits
and switches branches normally.

### thaw is guarded — it refuses to silently drop live-only tasks, notes, or dep edges

`thaw` rebuilds the live DB by dropping every task, **every note, and every dep
edge** and reinserting from `tasks/*.json`, so any row that exists **only** in
`taskdb.sqlite` — a task, note, or dependency edge a parallel session just minted
but has not `freeze`d + committed yet — would be erased. Before mutating anything,
`thaw` diffs the live task IDs against `tasks/task-*.json`, the live note IDs
against `tasks/note-*.json`, **and** the live `task_deps` edge set against the
union of every frozen task's `depends_on` array; if the rebuild would drop rows of
any kind, it **refuses** with a non-zero exit, a per-kind dropped count, and the
full list labelled by kind (dep edges named `A -> B`):

```sh
$ taskdb thaw
taskdb: refusing to thaw: 1 live-only task(s), 1 live-only note(s), and 1 live-only
dep edge(s) would be DROPPED (present in taskdb.sqlite, absent from tasks/*.json):
  task 01KTXV7YVSX4W6GD051113X6TN
  note 01KTXWPZ0CD1DKBSXKG0TKEN4D
  dep edge 01KTXV7YVSX4W6GD051113X6TN -> 01KTXWPZ0CD1DKBSXKG0TKEN4D

these rows have not been frozen to tasks/*.json, so a thaw would erase them.
to keep them: run `taskdb freeze` (then commit tasks/) before thawing,
or, if you intend to discard them, re-run with `taskdb thaw --force`.
recover with: taskdb freeze && git add tasks/ && taskdb thaw
```

The refusal runs **before** any transaction opens, so a blocked thaw never
mutates the DB; the copy-pasteable `taskdb freeze && git add tasks/ && taskdb thaw`
one-liner on the last line is the full recovery (freeze the live-only rows, stage
them, then thaw cleanly). Pass `--force` only when you mean to discard them; the
forced run reports what it dropped, naming each dropped task, note, **and** dep
edge so the discard is on the record, never silent. A thaw with **no** drops still
exits 0, so the non-interactive post-checkout/merge/rewrite hooks keep working
unchanged.

The refusal above is the **manual** default (`taskdb thaw` with no flags), and it
stays that way — a flagless thaw always refuses so an operator never loses
live-only work by accident. The **hook** path is different: the `post-checkout`,
`post-merge`, and `post-rewrite` hooks invoke `thaw --auto-freeze`, which turns
the refusal into an automatic remedy instead of a stale-DB stall (see below).

#### `--auto-freeze` — the hook-path remedy (docs/23 OQ3)

A hook-driven thaw runs non-interactively: on a bare refusal it can only print a
banner and leave the live `taskdb.sqlite` **stale** versus the just-landed
`tasks/*.json`, and the session keeps working against the stale DB until someone
notices. `taskdb thaw --auto-freeze` (also enabled by `TASKDB_THAW_AUTOFREEZE=1`)
closes that gap: when — and **only** when — the refusal cause is the live-only
DROP-guard, it additively writes `task-`/`note-*.json` for exactly the dropped ids
and unions each live-only dep edge into its owner task's on-disk JSON (via the
same `writeJSON` path `freeze` uses, so a pre-existing owner's other fields are
never touched), emits a one-line notice, then proceeds with the thaw. The
drop-diff is empty by construction at that point (recomputed and asserted before
the DB is touched), so the rows end up in **both** stores: rebuilt into the live
DB *and* left on disk as **untracked** `tasks/*.json` that travel with the next
commit (the pre-commit hook stages `tasks/` wholesale). A pull into a checkout
holding live-only rows thus rebuilds the DB **without `--force` and without
dropping anything**.

`--auto-freeze` is deliberately narrow. It intercepts ONLY the live-only-drop
cause, which is checked **before** any transaction opens; a **FOREIGN KEY** /
dangling-reference error surfaces later, inside the thaw transaction (where thaw
prunes+warns — see below), so `--auto-freeze` can never mask an FK error or a
genuine failure. When a hook-driven `thaw --auto-freeze` still exits non-zero, the
hooks print a loud `taskdb thaw FAILED` banner to **stderr** (framing that the DB
is stale, and distinguishing an FK error — *not* helped by `--force` — from a
genuine failure to inspect); this is now a real problem, never the routine
drop-guard case. The missing-binary and linked-worktree no-op paths stay silent as
before.

The notes and dep-edge halves close the same loss class one table over: a note
minted live but not yet frozen, or a dep edge minted live (`taskdb task dep A --on
B`) on an already-frozen task A — invisible to the task/note guard because A's row
exists in both stores and only its edge set differs — were silently dropped by the
same drop-and-reinsert until these guards covered them.

**Locks are runtime-only and intentionally excluded from the guard diff.**
`tasks.locked_by` / `locked_at` are tagged `json:"-"`, so they are never
serialized to `tasks/*.json` and never exist in the frozen JSON store. The thaw
guard only diffs rows and edges that *can* appear in the canonical JSON; locks
cannot, by design (see "Locking model" below). Instead of refusing, thaw saves
the live claims in-memory before the drop-and-reinsert and restores them
afterwards, so a hook-driven thaw never releases a running agent's lock. A held
lock neither causes a thaw refusal nor is dropped by one — the lock is still
held after thaw returns.

Restoring a claim is **changed-canonical-state-wins**, not blind: the lock is
re-applied only to a row that survives the reinsert and is not frozen-terminal.
Four branches fall out of that rule:
(1) a task frozen `done`/`blocked` keeps its terminal status and drops the
in-flight claim — a finished task beats an unfrozen in-progress flip; (2) a task
absent from `tasks/*.json` (deleted on a branch switch; reached only under
`--force`, since the drop-guard otherwise refuses) is not reinserted, so there is
no row to carry the lock onto and the claim is dropped with it; (3) a task frozen
`open` that a running agent claimed (live `in-progress` + lock) carries the lock
**and** flips the reinserted row back from `open` to `in-progress`, so the agent
never sees a silent status regression; (4) the claim's `branch` field rides the
same rule — the live lock row's branch is carried back only onto a reinserted
row whose frozen branch is **empty**, so a frozen non-empty branch wins and the
live one is not carried. All four branches are pinned by explicit tests in `thaw_test.go`:
`TestThawRestoreClaimsTerminalDrop` (1), `TestThawRestoreClaimsDeletedTask` (2),
`TestThawRestoreClaimsOpenToInProgress` (3), and `TestThawRestoreClaimsBranchCarry` (4).

That doc-comment index is itself drift-guarded (wave16b):
`TestThawRestoreClaimsIndexMatchesTestFuncs` in `thaw_test.go` parses the
"Branch coverage index" block out of `thaw.go` and cross-checks it against the
real `func Test…` names in the package — every indexed name must resolve to a
real test (no phantom entries) and all four pinned branches must stay indexed
(no silent removal). Both sides are recomputed from live source, never
literal-frozen, so renaming a test together with its index entry stays green
while a one-sided edit fails.

This guard exists because two 2026-06-12 incidents (5+ parallel waves) wiped
live-only tasks: an external thaw dropped 8 rows, and `taskdb thaw --help` — which
did not parse subcommand flags — executed a real thaw and dropped 13. Every
flagless verb (`thaw`, `freeze`, `status`, `task rm`, `note rm`) now **rejects**
an unrecognized flag with a usage error instead of silently ignoring it, so
`thaw --help` errors out rather than thawing. There is no per-subcommand
`--help`; run bare `taskdb` for usage.

## Common commands

```sh
# Create tasks (a ULID is returned; --json for scripting)
taskdb task add --title "Wire up egress gateway" --priority 2
taskdb task add --title "dnsgate conformance tests" --parent 01KTWQDYS8

# See what's there
taskdb task list                 # table
taskdb task list --tree          # parent/child tree
taskdb task list --status open
taskdb task list --ready         # dispatchable now: open, unlocked, deps done

# Declare ordering (a DAG — cycles are rejected with the offending chain)
taskdb task dep   01KTWS64SR --on 01KTWQDYS8   # can't start until the other is done
taskdb task undep 01KTWS64SR --on 01KTWQDYS8

# Move a task along
taskdb task set 01KTWQDYS8 --status in-progress
taskdb task edit 01KTWQDYS8 --priority 3
taskdb task edit 01KTWS64SR --parent 01KTWQDYS8  # regroup under an epic ('none' detaches; parent cycles rejected)

# Claim a task so a parallel session won't double-work it
taskdb task lock   01KTWQDYS8 --session "$MY_SESSION"
taskdb task unlock 01KTWQDYS8 --session "$MY_SESSION"

# Notes, free-standing or attached to a task
taskdb note add --task 01KTWQDYS8 --body "blocked on proto freeze" --author me
taskdb note list --task 01KTWQDYS8

# State of the world: counts + held locks (flags stale locks > 30 min)
taskdb status
```

### IDs are prefixes

IDs are ULIDs, but you rarely type the whole thing — any **unambiguous prefix**
works, case-insensitive, anywhere an ID is accepted:

```sh
taskdb task lock 01ktwqdys8 --session me   # resolves if the prefix is unique
```

If a prefix is ambiguous, the command lists the candidates instead of guessing.
`list` and `tree` print full ULIDs, so there's always a handle to copy.

## Dependencies & dispatch

`parent_id` is grouping (epics for `--tree`); `depends_on` is ordering (a DAG
read by dispatch). A task is **ready** when it's open, unlocked, every
dependency is done, and it has no children (epics aren't dispatched — they
finish when their children do). The agent loop is `list --ready` → `lock` →
work → `set --status done` → `unlock`; finishing a task is what unblocks its
dependents. Edges freeze into the dependent task's JSON as `depends_on`, so
the graph travels through git with everything else. See doc 21 § "Dependency DAG
& dispatch".

## TUI explorer

`taskdb tui` opens a read-only, full-screen explorer over the live DB (it is
classified as a read verb, so it also runs against a 0444 wave-sandbox
snapshot). Three views plus a per-task drill-down:

- **1 DAG** — the dependency forest in execution order: roots are tasks with
  no `depends_on` (the entrypoints), children are dependents (what finishing
  the parent unblocks). A task reachable through several parents is expanded
  once; later occurrences render as a dim `⤴` reference.
- **2 Epics** — the `parent_id` grouping tree, with a done/total descendant
  count per epic.
- **3 Ready** — the dispatch queue, exactly `task list --ready`, in priority
  order.
- **c Chain** — everything about the selected task: its transitive upstream
  deps (what gates it) and downstream dependents (what it unblocks); `esc`
  returns, `enter` re-centers on another task.

The right pane shows the selected task in full: status (with a `▶ ready now`
marker), epic, lock holder, deps/blocks/children with status glyphs, the
body, and every note. `/` filters by title/ID (matches keep their ancestor
chain visible), `s` cycles a status filter, `r` reloads from the DB, `?` has
the full key map. Glyphs: `▶` ready, `○` open, `◐` in-progress, `✕` blocked,
`●` done.

## Locking model

`lock` is atomic (`UPDATE … WHERE locked_by IS NULL` under SQLite WAL): the
second session to claim a task gets a non-zero exit and the current holder on
stderr. `unlock` only releases your own lock unless you pass `--force`. Locks
are runtime-only — they are **not** frozen to JSON, so they never travel across
branches or commits. `taskdb status` flags locks held longer than 30 minutes;
clear a dead one with `taskdb task unlock <id> --force`.

Because locks are runtime-only, a `thaw` (drop-and-reinsert) carries live claims
across the rebuild in-memory so a hook-driven thaw never releases a running
agent's lock, and it refuses outright to drop a **live-only task, note, or dep
edge** unless `--force` is set (see "thaw is guarded" above) — together these keep a thaw on
the shared primary checkout from stomping a parallel session's in-flight work.

### Shared lock server (coordinating across machines)

The SQLite lock columns coordinate parallel sessions on **one checkout**. To let
agents on **different machines** avoid double-claiming the same task, taskdb can
acquire locks in a shared Postgres registry reached over an SSH tunnel. It is
**enabled by default** via the committed `lockserver.json`, and it stores
nothing but lock rows — `tasks/*.json` in git stays the sole authority for task
content and the DAG.

`lock`/`claim`/`unlock`/`release`/`reap` (CLI **and** MCP, since they share the
`claimTask`/`releaseTask` cores) acquire in Postgres first, then mirror the hold
into the local SQLite columns so every existing reader (`readyWhere`, `list`,
`tui`, `task_report`) is unchanged. If the server is configured but unreachable
(no tunnel), taskdb prints one loud banner and **falls back to local-only**
locks so work is never blocked; `TASKDB_LOCK_DISABLE=1` silences it for
deliberate solo work, and `TASKDB_LOCK_DSN` overrides the connection.

A holder proves liveness by emitting **heartbeats** (`taskdb wave-event
... --event heartbeat`, written to `lock_heartbeats`). Beyond the manual
`lockserver reap`, an **activity-aware automatic reap** ages out an orphaned
hold with no operator verb: it fires opportunistically at the top of every
remote claim and in the landing-queue leader's idle loop, freeing a lock only
when **both** its `locked_at` and its freshest heartbeat are past the age (or
there is no heartbeat at all — a crashed agent), so a live heartbeating holder is
never evicted. A **specific-task claim** (`task claim <id>`) scopes the sweep
to just that task's lock (one row considered, not a full-table scan), while an
auto-claim and the leader's idle loop stay the global broom; either way a
claim-time sweep that frees a lock **logs the freed id(s) and a count to
stderr** rather than reaping silently. The age is `TASKDB_LOCK_AUTOREAP_AGE`
(Go duration, default 2h; non-positive/`off`/malformed disables); the
`__land_leader__` sentinel is always excluded. Details:
[`LOCKSERVER.md`](LOCKSERVER.md).

```sh
taskdb lockserver check        # is it configured / reachable / migrated?
taskdb lockserver check --strict  # wave pre-flight gate: exit non-zero if enabled-but-unusable (down tunnel / no schema)
taskdb lockserver tunnel       # print the ssh -L tunnel command (or --open to run it)
taskdb lockserver status       # locks held across ALL machines (the shared truth)
```

Full setup, provisioning, and per-dev onboarding: [`LOCKSERVER.md`](LOCKSERVER.md).

## Dispatch layer

These verb families drive the concurrent-agent dispatch layer (the worktree
workflow, the MCP server, and the dispatcher). Full design: doc 22 (dev
dispatch design).

```sh
# Task dispatch verbs (atomic claim → work → release; reap stale, search by text)
taskdb task claim   [<id>] --session "$S"          # atomically lock the highest-priority ready task (or a named one)
taskdb task release <id>   --session "$S" --status open|blocked|done [--note "..."]
taskdb task reap    [--age 30m] [--requeue] [--dry-run]   # force-release stale locks; --requeue reopens orphaned in-progress
taskdb task search  <query> [--limit 20] [--raw]   # full-text search over task title/body (FTS5)

# Worktree registry (registry only — provisioning lives in the dispatcher's
# worktree-setup script; its `Worktree ready:  <path>` output line is a pinned
# contract the pool cold path parses)
taskdb worktree register <id> --path <abs> --branch <b> --base <commit>  # records the worktree; sets tasks.branch
taskdb worktree list                               # what's running where, joined with task title/status
taskdb worktree unregister <id> [--clear-branch]   # drop the row; --clear-branch empties tasks.branch
taskdb worktree prune [--dry-run]                  # drop rows whose path no longer exists on disk

# Run ledger (the dispatcher writes one row after each agent exits)
taskdb run record --task <id> --session "$S" --status done|blocked|stuck|at_limit|error|timeout|killed|discarded [...]
taskdb run list   [--task <id>] [--limit 50]       # ledger view, newest first

# Doc index (markdown on disk is the truth; the DB is a derived FTS index)
taskdb doc sync   [--prune]                        # reindex README + docs/**/*.md, rebuild task↔doc links
taskdb doc search <query> [--limit 10] [--scope docs|tasks|all] [--raw]  # FTS5 search (implicit sync first)
taskdb doc get    <path-or-suffix> [--section <h>] [--outline]          # fetch a doc, a section, or its outline
taskdb doc link   <id> <doc-path> [--section "§4"]  # append a citation to the task's Sources: line
taskdb doc embed  --embedder-cmd CMD [--prune]      # index new/changed chunks (unchanged hashes never re-embed; docs/22 §8)
taskdb doc search <query> --semantic --embedder-cmd CMD  # cosine-ranked embeddings search (pure-Go ranking; embedder/ ships a reference embedder)
taskdb doc embed  --service-url URL --backfill-provenance  # also heal resident chunks pushed with empty provenance (targeted, no full reindex; see "Healing resident-service provenance" below)
# Operator tuning of the dense/sparse hybrid (weights, RRF k, index DB, ingest batch, live embedder): see scripts/taskdb/searchsvc/README.md "Operator env knobs".

# Audit (deterministic DAG/doc/stuck signals — no LLM, the curation workflows' input)
taskdb audit drift                                 # doc drift vs the last reconciliation watermark
taskdb audit stuck [--age 24h]                     # stale locks, orphaned in-progress, dangling worktrees
taskdb audit dag                                   # dependency cycles, all-done epics, unsourced/poison tasks
taskdb audit all                                   # the three above, grouped by workstream root
taskdb audit watermarks                            # read-only doc-audit watermark count + OQ5 superseded gauge

# MCP server (stdio; profile-gated tool surface for Claude agents)
taskdb mcp [--profile worker|curator] [--session "$S"]
```

Every verb takes `--json` for machine-readable output; that is the contract the
dispatcher and curation workflows read.

### `taskdb work` — the triage view, its buckets, and contention surfacing

`taskdb work` (alias `taskdb audit work`) triages the `--ready` frontier into
buckets and shows the **substantive** set grouped by root epic, so a mature
roadmap's wall of engine-generated bookkeeping doesn't drown the real work (see
the dispatch runbook §1.1). It is strictly read-only (SELECTs + filesystem reads). Beyond the python
`ready-work.py` it promotes, it adds two things:

- **Contention awareness.** It cross-references the live lock holders and the
  `.claude/worktrees/agent-*` trees a parallel session has checked out, flagging
  any ready task another session is actively working (a worktree edit holds no
  taskdb lock, so `--ready` alone cannot exclude it). An `agent-*` directory on
  disk with **no registry row** cannot be attributed to a specific ready task,
  so rather than guess it is surfaced as an aggregate footer that **names** the
  orphaned trees (`N unregistered agent-* tree(s) on disk … glance manually:
  agent-ab, agent-cd`), so an operator no longer has to `ls .claude/worktrees`
  to learn which trees are orphaned. The human footer is **bounded**: it lists at
  most **8** basenames inline and collapses the rest into `, and N more`, so a
  pathological worktrees dir (dozens of stale checkouts) never smears the footer
  across the terminal — the full set always rides `--json`. The count rides
  `--json` as `unregistered_agent_trees`, and the full, name-sorted set as the
  omit-empty `unregistered_agent_tree_names` (`len == unregistered_agent_trees`).
  Each `unregistered_agent_tree_names` **entry is an object**
  `{"name", "mtime", "age_secs"}` — the dir basename, its modification time
  (RFC3339, UTC; omitted if the stat failed), and its age in whole seconds at
  scan time — so live-vs-stale (a fresh mtime = a session still editing; a stale
  one = an abandoned checkout) is legible from `--json` alone. **Field-shape
  note:** `unregistered_agent_tree_names` changed from a bare `[]string` of
  basenames to this `[{name, mtime, age_secs}]` object array when per-orphan
  mtime/age was added; a consumer that read it as a string list must now read
  `.name`. Naming the trees does **not** attribute any of them to a task — the
  no-guess invariant is preserved; registered trees stay attributed to their task
  and are never re-listed as orphans.

- **Config-driven bucket keywords (`TASKDB_WORK_BUCKETS`).** The classification
  heuristics live in a rule table (bookkeeping → gated → strategic → docs →
  else `substantive`, first-match-wins) that an operator can **retune without
  recompiling**. Point `TASKDB_WORK_BUCKETS` at a JSON file, or drop a
  `scripts/taskdb/work-buckets.json` under the repo root (auto-loaded when the
  env var is unset), and it replaces the built-in `defaultBucketRules`:

  ```sh
  export TASKDB_WORK_BUCKETS=/path/to/work-buckets.json   # explicit override
  # …or just create scripts/taskdb/work-buckets.json (picked up automatically)
  ```

  A checked-in [`work-buckets.json.example`](work-buckets.json.example)
  reproduces the defaults verbatim — copy it to `work-buckets.json` (drop the
  `.example` suffix) and edit the `patterns` to taste. Each rule is
  `{"bucket", "scope", "patterns"}`: `scope` is `title` or `body` (title + body;
  the default when omitted), `patterns` are case-insensitive regex alternatives,
  and an empty pattern list disables that bucket. Keys beginning with `_` (e.g.
  the example's `_README`) are ignored by the loader, so they are safe inline
  docs. A malformed override is a **loud error**, never a silent fall-back to
  defaults. The loader only auto-loads the no-suffix `work-buckets.json`; the
  `.example` file is inert.

### Wave SDK & landing-queue introspection (the agent-scriptable orchestration verbs)

The `wave` verb group is a composable, agent-scriptable SDK over the wave
telemetry seam: an agent (or a monitoring script) can RECORD transitions and
INSPECT live wave status in one call each. Like `wave-event` and `landq`, these
are **remote-only** (they touch only the shared Postgres `wave_events` /
`lock_heartbeats`, never the local SQLite DB) and **fail-open** (a disabled /
unreachable lock server reports `reachable:false` and exits 0 — telemetry never
blocks a wave). The legacy `wave-event` / `wave-event list` calls are unchanged.

```sh
# Record ONE transition (same flags as `wave-event`); --json → {recorded,reachable,task}
taskdb wave report --wave W --run R --unit U --task <id> --phase implement --event start \
                   --status in-progress --session "$S" --tokens 1234 --note "..." --json

# Record a BATCH in one transaction (a JSON array from a file or stdin); --json → {recorded:N,reachable}
echo '[{"wave":"W","unit_key":"u1","phase":"review","event":"end","status":"done"}]' \
  | taskdb wave report --batch - --json

# Pre-rolled LIVE per-unit status (rollup joined with activity-aware staleness)
taskdb wave status --wave W [--run R] [--unit U] [--json]
#   --json → {units:[{unit,task,phase,status,event,events,updated_at,stale,active_secs}],reachable}

# Recent events newest-first; --follow polls ~2s and streams new ones
taskdb wave tail --wave W [--run R] [--limit N] [--follow] [--json]

# Is the landing runner up / who leads? (the landLeaderSentinel holder)
taskdb landq leader [--json]
#   --json → {leader:<session>|null, host, held_secs, reachable}

# Full status as one JSON object (counts + ready + notes + landq depth + held locks w/ staleness)
taskdb status --json   # the default human table is unchanged
```

#### Compose your own wave (the SDK as orchestration primitives)

`task-wave.js` is the full-featured engine, but it is just one consumer of these
verbs. An agent driving a **complex, bespoke task** doesn't have to inherit the
whole engine — it can compose the same primitives directly, in bash or from a
sandboxed workflow (`agent()` shelling out to `taskdb`). Every verb below emits
`--json` and is fail-open, so the loop is scriptable end-to-end. The shape mirrors
the engine's scope → implement → gate → land, and lands through the **serialized
landing queue** (doc 27 Lever 3) exactly like a real wave:

```sh
WAVE=myfeature; S="agent-$WAVE"; BASE="$(git -C "$REPO" rev-parse origin/main)"
RUN="$WAVE-${BASE:0:12}"                       # per-dispatch id (engine convention)

# ── SCOPE: claim the ready units you'll work (atomic; cross-machine via the lock server)
for id in $(taskdb task list --ready --json | jq -r '.[].id' | head -3); do
  taskdb task lock "$id" --session "$S" && taskdb task set "$id" --status in-progress
  taskdb wave report --wave "$WAVE" --run "$RUN" --unit "$id" --task "$id" \
                     --phase scope --event start --status in-progress --session "$S"
done

# ── IMPLEMENT each unit (your own work here), reporting progress so it shows live
#    Watch from anywhere:  taskdb wave status --wave "$WAVE" --json
taskdb wave report --wave "$WAVE" --run "$RUN" --unit "$id" --task "$id" \
                   --phase implement --event heartbeat --status in-progress --session "$S" \
                   --note "what I'm doing right now"      # refreshes the liveness heartbeat

# ── GATE on a self-contained integration branch (base-UNIQUE name avoids stale-ref reuse)
INTEG="$WAVE-integration-${BASE:0:12}"
git -C "$REPO" push origin "$INTEG:$INTEG"               # branch push only, never main
GATE='cd orchestrator && go build ./... && go test ./...'   # your real compose-build

# ── LAND: enqueue; the single elected leader re-runs GATE on (main ⊔ INTEG) and FF-lands.
#    Don't push main yourself — funnel through the queue so two landings never race.
taskdb landq enqueue --branch "$INTEG" --base "$BASE" --wave "$WAVE" --run "$RUN" \
                     --gate "$GATE" --tasks "$id1 $id2" --session "$S" --json
taskdb landq leader --json        # is the runner up? who leads?
taskdb landq list                 # watch your row reach 'landed' (or 'conflict'/'failed')

# ── FINALIZE once landed: terminal statuses unblock dependents; release the locks
taskdb task set "$id" --status done && taskdb task unlock "$id" --session "$S"
taskdb wave report --wave "$WAVE" --run "$RUN" --unit "$id" --task "$id" \
                   --phase finalize --event status-change --status done --session "$S"
```

This is the whole contract: **claim → report → gate → `landq enqueue` → watch →
finalize.** The leader (`taskdb landq run`) owns the serialized FF-land; you never
touch `main` directly. For status across machines, `taskdb wave status --json`
(pre-rolled per-unit rollup + activity-aware staleness) and `taskdb landq leader`
are the read side. The same calls work verbatim inside a sandboxed workflow via
`agent()` — the engine itself is built this way.

### Superseded-watermark count (read-only reopen-trigger gauge)

`audit drift` keeps the *newest* `doc-audit:` watermark note per doc path as the
reconciliation baseline (docs/22 §2.3); the older ones are retained as audit history
(**keep-all-for-now**, docs/22 §10 OQ5). OQ5's reopen trigger fires when superseded
watermarks (matching notes that are *not* the newest per path) exceed **~50**. To see
how close you are — on demand, no daemon, no watcher, no judge model — read the gauge
straight out of the live store with the in-binary read-only verb:

```sh
taskdb audit watermarks          # watermarks: M matched, B baselines, S superseded (OQ5 trigger 50)
taskdb audit watermarks --json   # {"matched":M,"baselines":B,"superseded":S,"trigger":50,"tripped":false}
```

It reuses `audit drift`'s own `auditWatermarks()` for the newest-per-path baseline,
so `baselines` is exactly what `audit drift` reconciles against; `superseded` =
`matched` − `baselines`. Watermark notes are taskless (`task_id IS NULL`) and are
counted through the same in-tree matcher `audit drift` uses — `auditWatermarkNoteRe`
in `scripts/taskdb/cmd_audit.go`, whose canonical parse shape (`doc-audit: <path> @
<hash7> ok …`) lives in docs/22 §2.3 — so the count never drifts from the baseline
parser. Non-matching notes are never counted and a single-note doc contributes 0.
`tripped` is set once `superseded` reaches the OQ5 threshold. The reading is purely
informational — nothing is mutated, no rows are dropped. The mechanical follow-up once
the trigger fires (a `note prune` sweep) is **deferred** and does not ship today
(docs/22 §10 OQ5); seed doc-audit baselines first, then revisit.

### Healing resident-service provenance (`doc embed --backfill-provenance`)

A long-lived **resident** searchsvc accumulates chunks from `doc embed --service-url`
pushes as you work — the push streams the changed chunk set into the running index
without a full rebuild. Chunks streamed **before** the provenance-pushers fix landed
with **empty** `doc_path`/`heading`, so their `/search` hits show no source until the
next full `/reindex` rebuilds the resident metadata from disk. `--backfill-provenance`
heals exactly those chunks **without** a full reindex:

```sh
taskdb doc embed --embedder-cmd CMD \
  --service-url http://127.0.0.1:8099 \
  --backfill-provenance
```

What it does: after the normal changed-set push, the embed run POSTs the service's
`/backfill_provenance` route, which scans the resident index for chunks whose
`doc_path` **and** `heading` are both empty, re-resolves each from the index DB's
`doc_chunks` (keyed by `chunk_hash`), and rewrites the resident metadata **in place**
(the existing dense vector is preserved — only the provenance is refreshed). It is a
**targeted** heal, not a corpus reindex: untouched chunks are not re-embedded and the
matrix is not rebuilt. On success the run prints
`backfilled provenance: N resident chunks healed → searchsvc`.

When to use it: **once, after upgrading a long-lived resident service** past the
provenance fix — to heal the chunks it absorbed before the upgrade — instead of paying
for a full `/reindex`. A fresh service, or one whose chunks all carry provenance, finds
nothing to heal (0 chunks) and the flag is a harmless no-op.

Flag/route contract:

- `--backfill-provenance` is **additive, defaults OFF, and requires `--service-url`** —
  with no `--service-url` it is a silent no-op (there is no resident service to heal).
- It is **fail-open**, identical to the push: an unreachable service emits one loud
  `[searchsvc DEGRADED]` banner and the embed run still succeeds; the heal is an
  optimization, never a gate.
- The underlying route is `POST /backfill_provenance` on the searchsvc instance,
  returning the additive summary `{"healed", "scanned", "empty", "unresolved", "db"}`.
  See `scripts/taskdb/searchsvc/README.md` for the searchsvc wire contract and operator
  env knobs.

## The `branch` column ritual

The dispatch layer adds one frozen column — `tasks.branch` — alongside several
ephemeral tables (worktree registry, run ledger, agent reports, doc index) that
are never frozen. Applying the column is the standard drop-and-thaw ritual: the
schema change lives in `db.go`/`model.go`, and you rebuild the live DB from
canonical JSON to pick it up:

```sh
rm taskdb.sqlite*    # drop the live store (canonical state is in tasks/)
taskdb thaw          # rebuild it from tasks/*.json with the new schema
taskdb freeze        # write it back out
git diff tasks/      # MUST be empty — no task has a branch yet, so JSON is byte-identical
```

The empty diff is the acceptance gate: `branch` serializes `omitempty`, so a
task's JSON gains the field only once a worktree is provisioned for it.

The leading `rm taskdb.sqlite*` is load-bearing for the guard above: it drops the
live store first, so the rebuilding `thaw` starts from an empty DB with no
live-only rows and never trips the drop-refusal. If you have unfrozen live-only
tasks you must keep, `taskdb freeze` them (and commit `tasks/`) *before* the `rm`,
not after.
