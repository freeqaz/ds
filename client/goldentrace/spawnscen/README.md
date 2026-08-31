# spawnscen/ — THE canonical spawn-scenario table (cycle-free leaf)

**Charter:** the single canonical home for the spawn-scenario ENUMERATION — the
pure-data `SpawnScenario` table (Fixture join key + shared facts) and the
`NegativeControlFixtures` list — that both the read side (`../replay`) and the
write side (the in-package `claudecode` driver test) drive their spawn coverage
from.

**Owner:** Attach & client · **OSS** (Apache-2.0; `client/` is wholly OSS, so
this falls inside the `client/` license glob — no `oss-manifest.yaml` edit) ·
**Decisions:** D18, D38, D49, D50.

**No proto seam.** This is in-repo TEST-ENUMERATION data — a list of fixture
names and the facts the test harness agrees on — NOT a service boundary. It
crosses no process, so it reserves no `proto/` seam (D24/D58/D80 do not apply);
the `guardrail-map.yaml` glob for this dir carries tags `[]` for the same reason
`docs/` and `raw/` do: changing test-enumeration data costs full-matrix CI time
if unmapped, never coverage (D47).

## Why this package exists

The spawn classifier is single-sourced (`classify.go`'s `IsSpawnToolUse`), but
the fixture TABLE used to live as TWO hand-kept mirrors — `replay.SpawnScenarios`
(goldentrace) and `spawnScenarioFixtures` (the adapter test) — because the two
suites live in different Go packages with NO cycle-free shared home: `claudecode`
cannot import `replay` (goldentrace already imports the adapter → a back-edge
would cycle). This package IS that cycle-free home: a LEAF that imports nothing
from `client/`, so BOTH `replay` and the in-package `claudecode` test can import
it without a cycle. The second hand-kept copy is retired; the table is single-
sourced here.

## What must NOT live here (and why)

- **No classifier logic.** The spawn discriminator `IsSpawnToolUse` stays in
  `classify.go` (D38, single-sourced). Putting it here — or any helper that
  calls it (`DiscoverSpawnFixtures`, `cassetteIsSpawnPath`, `lineHasSpawnBlock`
  and their write-side twins) — would make this leaf import the adapter, and
  goldentrace already imports the adapter, so the back-edge would re-create the
  exact import cycle this leaf exists to avoid. Those discovery helpers STAY
  per-side.
- **No fixtures.** This table NAMES the cassettes (`client/fixtures/*.cc-wire.ndjson`);
  it does not hold their bytes. The negative-control bytes likewise stay in-test
  on each side.
- **No adapter imports.** The leaf imports nothing from `client/` — that is the
  whole charter (the cycle constraint). Keep it that way.

## How honesty is kept

This table is not trusted to decide what fixtures "should" exist. Each side runs
a disk-vs-table completeness check — `TestSpawnScenarioTableComplete` (read) and
`TestSpawnScenarioTableMirrorsDisk` (write) — that re-globs `client/fixtures`,
classifies each cassette by content through the single-sourced `IsSpawnToolUse`,
and fails BY NAME if this table is missing (or carries a stale) spawn-path
fixture. The `depth3-nested-spawn` pin is re-asserted on both sides. Those
witnesses are unchanged by single-sourcing the table here (D50: synthetic
fixtures only).
