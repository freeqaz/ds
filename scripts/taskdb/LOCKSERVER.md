# taskdb shared lock server

Concurrent agents on **different machines** coordinate task locks through a
single Postgres registry, reached over an SSH tunnel. This is the only piece of
taskdb that uses a network service, and it stores **nothing but lock rows** —
the git repo (`tasks/*.json`) remains the single authority for task content,
dependencies, and the DAG. Losing the lock database loses no durable work.

```
  dev laptop                         lock-server host
  ┌────────────┐   ssh -L 5433: ─▶  ┌──────────────────────────┐
  │ taskdb     │   (tunnel acct,    │ sshd: tunnel acct may ONLY│
  │  └ lib/pq ─┼─▶ 127.0.0.1:5433   │ forward 127.0.0.1:5432    │
  └────────────┘                    │ Postgres (localhost-only) │
                                    │  └ db "taskdb" / devteam  │
                                    └──────────────────────────┘
```

Recommended posture: bind Postgres to localhost on the lock-server host and make
it reachable **only** through a dedicated forward-only SSH account, whose
`authorized_keys` gate every connection and which can do nothing but forward the
Postgres port (no shell, no other destination). A leaked DB password is then
inert without an authorized private SSH key.

## How it behaves

- **Disabled by default.** The committed `scripts/taskdb/lockserver.json` is an
  example with `"enabled": false`, so a fresh clone locks **locally** (per-clone
  SQLite) and never dials out. Opt in by editing that file with your own
  registry's coordinates, or simply by exporting `TASKDB_LOCK_DSN` (which both
  overrides the connection string and enables remote locking — no credential
  needs to be committed).
- `lock` / `claim` acquire the lock in Postgres first (the cross-machine
  authority), then mirror the hold into the local SQLite `locked_by`/`locked_at`
  columns so `list` / `tui` / `status` / `task_report` read consistent state.
- **Fail-open**: if the server is enabled but unreachable (you haven't opened
  your tunnel), taskdb prints one loud banner and falls back to **local-only**
  locks so work is never blocked — but cross-machine coordination is OFF until
  the tunnel is back. For deliberate solo work, set `TASKDB_LOCK_DISABLE=1` to
  silence the banner.
- Override the connection entirely with `TASKDB_LOCK_DSN` (a lib/pq DSN).

## Liveness heartbeats & automatic reap

A holder proves it is still alive by writing **liveness heartbeats** into the
`lock_heartbeats` table — this is what `taskdb wave-event ... --event heartbeat`
records, and what a running wave/agent emits as it works. The freshest
`last_activity` per task is the activity signal the reap predicate reads.

Two paths free a lock nobody is renewing, so a crashed wave's orphaned hold
never blocks its task indefinitely:

- **Manual** — `taskdb lockserver reap [--age 30m]` (or `taskdb task reap`),
  an operator verb.
- **Automatic (activity-aware, no operator verb)** — an opportunistic reap
  fires at the top of every remote claim (`task claim`/`list --ready`) and,
  rate-limited, in the always-on landing-queue leader's idle loop. It is
  **target-scoped** on a specific-task claim (`claim <id>`): only that one task's
  lock is considered (the cheap path — one candidate row, not a full-table scan,
  which matters under large parallel waves), so a specific-task claim never
  evicts an unrelated wave's stale hold. An **auto-claim** (no id) walks all ready
  candidates and keeps the full-table reap as its broom; the leader's idle loop
  remains the standing global broom. In every case a lock is reaped only when
  **both** its `locked_at` **and** its freshest heartbeat are older than the
  auto-reap age, with an age-only fallback for a lock that has **no** heartbeat
  rows at all (a crashed, non-emitting agent). So a live holder that is still
  heartbeating past the age is **never** evicted.

  A claim-time reap is **observable**, not silently swallowed: each freed id is
  logged to stderr, a best-effort `phase=claim event=reap` row is appended to
  `wave_events` (attributed to the claiming session, freed ids in its note — no
  `task_id`, so it never writes a false heartbeat for the claimer), and the freed
  ids ride the claim result as a **`reaped_locks`** field on `task claim --json`
  and the MCP `task_claim` payload. All of this is fail-open — a reap error, or an
  event-record error, never gates the claim.

The auto-reap age is `TASKDB_LOCK_AUTOREAP_AGE` (any Go duration; **default 2h**,
deliberately looser than the manual 30m default because heartbeat emission is
not yet universal). A non-positive value, the literal `off`, or a malformed
value **disables** the automatic reap (so a typo can never reap at a surprise
age); the manual verbs are unaffected. The `__land_leader__` election sentinel is
**always excluded** from every age-reap — manual or automatic — so a live
mid-backlog leader is never evicted out from under itself; clear a genuinely dead
leader with `lockserver unlock __land_leader__ --force`.

## One-time server provisioning (admin, on the lock-server host)

`devteam` should not have CREATEDB, so the dedicated database is created once
by the postgres superuser:

```sh
# copy scripts/taskdb/lockserver-provision.sql to the lock-server host, then:
sudo -u postgres psql -v ON_ERROR_STOP=1 -f ./lockserver-provision.sql
```

This creates the `taskdb` database (owned by `devteam`) and the `task_locks`
table. It is idempotent. After this, no further superuser action is ever needed
— `taskdb lockserver migrate` can re-apply the schema as `devteam` if required.

## Per-developer onboarding

0. **Point the repo at your lock server** — edit `scripts/taskdb/lockserver.json`
   (set `enabled`, `ssh.host`, `ssh.user`, and the Postgres block) or export
   `TASKDB_LOCK_DSN`.
1. **Get your SSH key authorized for the tunnel** (admin, once per dev): append
   your `~/.ssh/id_ed25519.pub` to the tunnel account's `authorized_keys` on the
   lock-server host, ideally with a `command=""`/`permitopen=` restriction that
   allows nothing but the Postgres forward.
2. **Open the tunnel.** On a long-lived box, run it under a supervisor (see
   "Supervised tunnel" below) so it survives shell exit and self-reconnects.
   For a one-off, run it ad-hoc (dies with its shell):
   ```sh
   SSH_HOST=lock.example.com scripts/taskdb/lockserver-tunnel.sh   # auto-reconnects
   # or, one-shot, using lockserver.json's values:
   .bin/taskdb lockserver tunnel --open
   ```
3. **Verify**:
   ```sh
   .bin/taskdb lockserver check      # enabled ✓ reachable ✓ schema ✓
   .bin/taskdb lockserver status     # held locks across ALL machines
   ```
4. Use taskdb normally — `task claim`, `task lock`, etc. now coordinate across
   every dev with the tunnel open.

## Operator commands

```sh
taskdb lockserver check               # diagnose config / reachability / schema
taskdb lockserver status [--json]     # locks held across all machines (the truth)
taskdb lockserver migrate             # (re)apply the schema, idempotent
taskdb lockserver tunnel [--open]     # print (or run) the ssh tunnel command
taskdb lockserver reap [--age 30m]    # clear stale shared locks (server clock; activity-aware, also runs automatically — see above)
taskdb lockserver unlock <id> --force # release one dead dev's lock
```

`taskdb status` also reports the shared locks when the tunnel is up, and notes
the degraded local view when it is not.

## Supervised tunnel

On a persistent box the tunnel should not depend on an interactive shell. Run
the forward under your init/process supervisor with restart-on-exit and SSH
keepalives — e.g. a `systemd --user` unit whose `ExecStart` is:

```
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
    -L 5433:127.0.0.1:5432 tunnel@lock.example.com
```

with `Restart=always`, plus `loginctl enable-linger "$USER"` so it stays up
across logout. Recovery is then a one-liner (`systemctl --user restart <unit>`);
the ad-hoc `scripts/taskdb/lockserver-tunnel.sh` remains the fallback. A
multi-agent wave gates on `taskdb lockserver check --strict` before it claims
anything, so a down tunnel aborts the wave with a restart hint instead of
letting it claim on invisible local-only locks.

## Rotating the DB password / revoking a dev

- Revoke a dev's tunnel access: remove their line from the tunnel account's
  `~/.ssh/authorized_keys` on the lock-server host.
- Rotate the DB password: `sudo -u postgres psql -c "ALTER ROLE devteam PASSWORD '…';"`
  then update `password` in `scripts/taskdb/lockserver.json` (or your
  `TASKDB_LOCK_DSN`) and rebuild taskdb.
