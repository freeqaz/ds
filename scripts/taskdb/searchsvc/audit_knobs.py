# SPDX-License-Identifier: Apache-2.0
#
# audit_knobs.py — searchsvc's "one knob, both legs" PARITY VERIFIER.
#
# WHY THIS EXISTS: the dense/sparse balance is meant to be a SINGLE operator knob
# that moves BOTH ranking legs at once — the Python fusion leg (fusion.py:
# W_DENSE / W_SPARSE, read from SEARCHSVC_W_DENSE / SEARCHSVC_W_SPARSE) and the Go
# ingest/search leg (embeddings.go: envWDense / envWSparse, the SAME env names,
# the SAME 0.65 / 0.35 canonical defaults). Each leg ALREADY logs its effective
# knobs at start (fusion.py._log_effective_knobs at import; Go
# logEffectiveIngestKnobs at ingest), but confirming the invariant "the two legs
# agree" today means scraping two stderr banners across two processes. This script
# resolves + prints the EFFECTIVE knobs for BOTH legs in ONE place and EXITS
# NON-ZERO when the shared W_ knobs diverge across the legs — so an operator (or
# CI) can assert parity with a single read-only command.
#
# WHAT IT REPORTS:
#   * W_DENSE / W_SPARSE  — the SHARED cross-leg knob, resolved for BOTH legs.
#   * SEARCHSVC_RRF_K     — fusion-ONLY (the Go leg blends raw cosines, has no RRF
#                           damping constant); reported for the Python leg only.
#   * DS_SEARCHSVC_INGEST_BATCH — Go-ONLY (the /ingest_batch chunk count); reported
#                           for the Go leg only.
#
# HOW EACH LEG IS RESOLVED (hermetic, read-only, no live model / GPU / network):
#   * Python leg: import fusion and read the bound module constants K_RRF / W_DENSE
#     / W_SPARSE — the real values the fusion module bound at load (env overrides +
#     loud-fallback already applied). This is the leg's own resolution, verbatim.
#   * Go leg: the Go ranker resolves W_DENSE / W_SPARSE from the SAME env names with
#     the SAME defaults (embeddings.go: envWDense/envWSparse, wDenseDefault=0.65,
#     wSparseDefault=0.35) and DS_SEARCHSVC_INGEST_BATCH from defaultIngestBatchSize.
#     Rather than hardcode those numbers, we PARSE the canonical defaults out of the
#     Go source so this audit tracks the actual landed Go defaults, then apply the
#     same env-override + parse-once + loud-fallback discipline the Go code uses. No
#     `go run`/`go build` is required (and `go` need not be installed) — the audit is
#     a pure read of the landed Go source's defaults + the current environment.
#
# PURE PYTHON. No numpy, no model, no GPU, no torch, no network. Read-only: it
# resolves and prints; it mutates nothing.

import json
import os
import re
import sys

# fusion.py lives beside this script. The searchsvc tests run with cwd =
# scripts/taskdb/searchsvc (uv project root), so a bare `import fusion` resolves.
# Belt-and-suspenders: ensure this script's own directory is importable so the
# audit works when invoked from elsewhere too.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

# Env var names — byte-for-byte the names BOTH legs read (fusion.py +
# embeddings.go). Keeping them in one place is what makes the audit honest.
ENV_W_DENSE = "SEARCHSVC_W_DENSE"
ENV_W_SPARSE = "SEARCHSVC_W_SPARSE"
ENV_RRF_K = "SEARCHSVC_RRF_K"
ENV_INGEST_BATCH = "DS_SEARCHSVC_INGEST_BATCH"

# The Go source whose canonical defaults we mirror. Resolved relative to this
# script so the audit tracks the landed Go code, not a hardcoded copy.
_GO_EMBEDDINGS = os.path.normpath(os.path.join(_THIS_DIR, "..", "embeddings.go"))
_GO_INGEST = os.path.normpath(os.path.join(_THIS_DIR, "..", "searchsvc_ingest.go"))

# Fallback defaults used ONLY if the Go source can't be read/parsed (so the audit
# still runs in a stripped checkout). These match the documented canonical values.
_FALLBACK_W_DENSE = 0.65
_FALLBACK_W_SPARSE = 0.35
_FALLBACK_INGEST_BATCH = 128


def _warn(msg):
    print("searchsvc/audit_knobs: " + msg, file=sys.stderr)


def _parse_go_default(path, const_name, cast, fallback):
    """Read ``const_name = <literal>`` out of a Go source file and cast it.

    Mirrors the Go leg's canonical defaults at the source of truth rather than
    duplicating the numbers here. LOUD-falls back to ``fallback`` if the file is
    unreadable or the constant isn't found — the audit never crashes on a moved
    line; it degrades to the documented value with a warning."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            src = fh.read()
    except OSError as exc:
        _warn(
            "cannot read Go source {!r} for {} ({}); using fallback default {!r}".format(
                path, const_name, exc, fallback
            )
        )
        return fallback
    # Match e.g.  wDenseDefault  = 0.65   or   defaultIngestBatchSize = 128
    m = re.search(
        r"\b" + re.escape(const_name) + r"\b\s*=\s*([0-9][0-9_.]*)", src
    )
    if not m:
        _warn(
            "could not find Go const {} in {!r}; using fallback default {!r}".format(
                const_name, path, fallback
            )
        )
        return fallback
    try:
        return cast(m.group(1).replace("_", ""))
    except (ValueError, TypeError):
        _warn(
            "Go const {}={!r} did not parse as {}; using fallback default {!r}".format(
                const_name, m.group(1), cast.__name__, fallback
            )
        )
        return fallback


def _env_number(name, default, cast):
    """Resolve env ``name`` with ``cast``, returning ``default`` if unset/empty and
    LOUD-falling back to ``default`` on a present-but-unparseable value — the exact
    discipline fusion.py._env_number and the Go envFloat / resolveIngestBatchSize
    use, so this script reports what each leg WOULD resolve, not an idealized value."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return cast(raw.strip())
    except (ValueError, TypeError):
        _warn(
            "ignoring invalid {}={!r} (expected {}); falling back to default {!r}".format(
                name, raw, cast.__name__, default
            )
        )
        return default


def resolve_python_leg():
    """Resolve the Python fusion leg's EFFECTIVE knobs by importing fusion and
    reading the constants it bound at load (env overrides already applied). This is
    the leg's OWN resolution, verbatim — not a re-derivation."""
    import fusion  # local import: triggers fusion's load-time _log_effective_knobs banner

    return {
        "w_dense": float(fusion.W_DENSE),
        "w_sparse": float(fusion.W_SPARSE),
        "rrf_k": int(fusion.K_RRF),
    }


def resolve_go_leg():
    """Resolve what the Go ranking/ingest leg WOULD use: the SAME env names with the
    Go source's canonical defaults (parsed from embeddings.go / searchsvc_ingest.go),
    applying the Go leg's parse-once + loud-fallback discipline. No `go` toolchain
    needed — a pure read of the landed Go defaults + the current environment."""
    w_dense_default = _parse_go_default(
        _GO_EMBEDDINGS, "wDenseDefault", float, _FALLBACK_W_DENSE
    )
    w_sparse_default = _parse_go_default(
        _GO_EMBEDDINGS, "wSparseDefault", float, _FALLBACK_W_SPARSE
    )
    batch_default = _parse_go_default(
        _GO_INGEST, "defaultIngestBatchSize", int, _FALLBACK_INGEST_BATCH
    )

    w_dense = _env_number(ENV_W_DENSE, w_dense_default, float)
    w_sparse = _env_number(ENV_W_SPARSE, w_sparse_default, float)
    # Go clamps the batch to >= 1 (loud fallback to the default below 1); mirror it.
    batch = _env_number(ENV_INGEST_BATCH, batch_default, int)
    if batch < 1:
        _warn(
            "{}={} must be >= 1 — using Go default batch size {}".format(
                ENV_INGEST_BATCH, batch, batch_default
            )
        )
        batch = batch_default

    return {
        "w_dense": float(w_dense),
        "w_sparse": float(w_sparse),
        "ingest_batch": int(batch),
    }


def _resolve_legs_and_divergences():
    """Resolve both legs and compute the cross-leg W_ divergence list. Shared by the
    human (``audit``) and machine-readable (``build_report``) outputs so the two can
    never disagree about what was resolved or whether parity holds."""
    py = resolve_python_leg()
    go = resolve_go_leg()

    # The shared W_ knobs are the parity invariant. Compare with an exact float
    # equality: both legs resolve from the SAME env string (or the SAME default),
    # so identical inputs MUST yield byte-identical floats — any difference is a
    # genuine name/default divergence, not float noise.
    divergences = []
    for label, key in (("W_DENSE", "w_dense"), ("W_SPARSE", "w_sparse")):
        if py[key] != go[key]:
            divergences.append(
                "{}: python={!r} go={!r}".format(label, py[key], go[key])
            )
    return py, go, divergences


def build_report():
    """Return a JSON-serializable dict of the EFFECTIVE knobs for both legs plus the
    parity verdict — the machine-readable twin of ``audit``'s human table, for CI to
    assert parity on. ``parity_ok`` mirrors ``main``'s exit code (True == exit 0).
    Pure / read-only: it resolves and returns; it mutates nothing and prints nothing."""
    py, go, divergences = _resolve_legs_and_divergences()
    return {
        "shared": {
            "W_DENSE": {"python": py["w_dense"], "go": go["w_dense"]},
            "W_SPARSE": {"python": py["w_sparse"], "go": go["w_sparse"]},
        },
        "python_only": {
            "SEARCHSVC_RRF_K": py["rrf_k"],
        },
        "go_only": {
            "DS_SEARCHSVC_INGEST_BATCH": go["ingest_batch"],
        },
        "parity_ok": not divergences,
        "divergences": list(divergences),
    }


def audit(out=None):
    """Resolve both legs, print the effective-knobs report, and return the list of
    cross-leg W_ divergences (empty == parity OK). Pure / read-only: it prints to
    ``out`` (default stdout) and resolves; it mutates nothing."""
    if out is None:
        out = sys.stdout

    py, go, divergences = _resolve_legs_and_divergences()

    print("searchsvc effective knobs (one-knob-both-legs parity audit)", file=out)
    print("  SHARED (cross-leg):", file=out)
    print(
        "    W_DENSE   python={!r}  go={!r}{}".format(
            py["w_dense"], go["w_dense"],
            "" if py["w_dense"] == go["w_dense"] else "   <-- DIVERGENT",
        ),
        file=out,
    )
    print(
        "    W_SPARSE  python={!r}  go={!r}{}".format(
            py["w_sparse"], go["w_sparse"],
            "" if py["w_sparse"] == go["w_sparse"] else "   <-- DIVERGENT",
        ),
        file=out,
    )
    print("  PYTHON-ONLY (fusion):", file=out)
    print("    SEARCHSVC_RRF_K        {!r}".format(py["rrf_k"]), file=out)
    print("  GO-ONLY (ingest):", file=out)
    print(
        "    DS_SEARCHSVC_INGEST_BATCH  {!r}".format(go["ingest_batch"]),
        file=out,
    )

    if divergences:
        print("  PARITY: FAIL — shared W_ knobs diverge across legs:", file=out)
        for d in divergences:
            print("    " + d, file=out)
    else:
        print("  PARITY: OK — shared W_ knobs agree across both legs.", file=out)

    return divergences


def main(argv=None):
    """Exit 0 when the shared W_ knobs agree across both legs; exit 1 on any
    cross-leg W_ divergence (so CI / an operator can gate on parity).

    ``--json`` swaps the human table for a single machine-readable JSON object on
    stdout (effective knobs for both legs + the parity verdict); the exit code is
    UNCHANGED (0 == parity OK, 1 == divergence), and the default (no-flag) human
    output is byte-for-byte unchanged."""
    if argv is None:
        argv = sys.argv[1:]

    emit_json = False
    for arg in argv:
        if arg == "--json":
            emit_json = True
        else:
            _warn("unknown argument {!r} (supported: --json)".format(arg))
            return 2

    if emit_json:
        report = build_report()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["parity_ok"] else 1

    divergences = audit()
    return 1 if divergences else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
