# Fixture provenance — D50

**Rule: if it is in git, it is synthetic.** No exceptions.

D50 (doc 04 §6) tags every test
fixture with a provenance class:

| Tag | Meaning | Where it may live |
|---|---|---|
| `synthetic` | Authored or generated; contains no real user/partner data, no real credentials | **Here** (version control), CI, the D26 public suite |
| `dogfood` | Recorded from internal use | Segregated internal store ONLY — never this repo |
| `partner-consented` | Recorded under design-partner consent/retention/revocation terms | Segregated internal store ONLY — never this repo |

Shipped suites run entirely on synthetic fixtures with zero data egress;
clean-by-construction beats scrub-and-hope (D50 rationale).

## What these fixtures are

These are hand-authored captures of the host-side introspection tools' textual
output, in the exact shape the v0 enumerate path parses (D29: the block
MECHANISM is out of scope — we parse `virt-diff` / `qemu-img` output, we never
open a qcow2):

- `virtdiff-*.txt` — synthetic `virt-diff -a <base.raw> -A <overlay.qcow2>`
  output (file-level delta of a destroyed session's overlay vs the read-only
  base). Never a real session capture — the paths are invented agent-workspace
  edits.
- `qemuimg-*.txt` — synthetic `qemu-img info --backing-chain <overlay.qcow2>`
  output (the D29 backing-file invariant: overlay → raw base).

Negative fixtures (`*-negative-*`, `*-nobacking-*`, `*-malformed-*`) exist so
the parser test is non-vacuous: each MUST fail the parser/assertion it targets.

## Tag format

Non-NDJSON fixtures carry the D50 provenance object in a `<name>.provenance`
sidecar file. `scripts/check-fixture-provenance.sh` scans this directory and
fails on a missing sidecar or any `provenance` value other than `synthetic`.

## Committed fixtures

| File | Shape | Class | Role |
|---|---|---|---|
| `virtdiff-conforming.txt` | virt-diff (plain) | synthetic | positive: added/deleted/modified rows + a header line + an --extra-stats column |
| `virtdiff-csv-spacepaths.txt` | virt-diff (--csv --extra-stats) | synthetic | positive: embedded-space + embedded-quote paths parse WHOLE (no first-whitespace truncation), honest counts |
| `virtdiff-mixed-shape.txt` | virt-diff (interleaved plain + --csv) | synthetic | DEGRADE-then-RECOVER: a genuinely interleaved capture — auto-detect commits to plain (so forced `--mode-plain` ERRORS, forced `--mode-csv` under-reports), but ModeAuto RECOVERS via the per-row classifier (DetectedMode=mixed), all 7 writes whole |
| `virtdiff-embedded-newline.txt` | virt-diff (interleaved plain + --csv, embedded `\n` in a quoted CSV path) | synthetic | LIMITATION GUARD: an RFC-4180 quoted path field carries an embedded literal newline. Whole-capture `parseVirtDiffCSV` joins it WHOLE (one csv.Reader over all input); the per-row classifier (ModeAuto on this non-homogeneous capture) bufio-scans line by line, so the physical newline is a record boundary BEFORE csv.Reader runs → unterminated-quote ERROR (never a silent drop). Pins the documented per-row single-line-record asymmetry |
| `virtdiff-csv-malformed.txt` | virt-diff (--csv) | synthetic | NEGATIVE: an unknown single-char status token in a CSV row → parse error |
| `virtdiff-malformed.txt` | virt-diff (plain) | synthetic | NEGATIVE: a known status char with no following space → parse error |
| `qemuimg-conforming.txt` | qemu-img info --backing-chain | synthetic | positive: overlay → raw base, one backing level |
| `qemuimg-nobacking.txt` | qemu-img info | synthetic | NEGATIVE: overlay with NO backing file → D29 violation |
