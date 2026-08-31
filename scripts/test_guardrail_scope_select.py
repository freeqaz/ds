#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the D47 fail-closed guardrail-scope selector.

Covers the done-when contract for scripts/guardrail-scope-select.py (doc 06 §3c
/ §4; D47, doc 04 §6):
  * unmapped path            -> full matrix (fail-closed)
  * meta-change (an edit to guardrail-map.yaml itself) -> full matrix
  * most-specific-glob precedence (a narrowing row never weakens a broader one)
  * the no-base / empty-diff sentinels -> full matrix
  * malformed map (no default.unmapped) -> fail-closed exit(2)
  * a path mapped to an EMPTY tag list (docs/**) is "no guardrail run", NOT
    unmapped (the distinction the fail-closed rule turns on)
  * full-matrix subsumes narrower tags when both are selected in one diff

Every test builds a SYNTHETIC fixture map in a temp dir — the live
guardrail-map.yaml is never read here (it is Boundary-owned and these tests
must not couple to its evolving row set).

Run from anywhere via:
    python3 -m unittest discover -s scripts -p 'test_guardrail_scope_select.py'
or directly:
    python3 scripts/test_guardrail_scope_select.py
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

# Load the selector module by path (it has a hyphenated filename, so a plain
# `import` is not possible). The repo root is one level up from scripts/.
_HERE = Path(__file__).resolve().parent
_SELECTOR = _HERE / "guardrail-scope-select.py"


def _load_selector():
    spec = importlib.util.spec_from_file_location("guardrail_scope_select", _SELECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sel = _load_selector()


# A synthetic map exercising the shapes the live map uses: a default.unmapped, a
# broad recursive row, a more-specific narrowing row beneath it, an empty-tag
# (docs-like) row, and the meta-change row for the map file itself.
SYNTH_MAP = """\
# synthetic fixture map — never the live guardrail-map.yaml
version: 0

default:
  unmapped: full-matrix

rules:
  - glob: "dataplane/**"
    tags: [boundary-conformance, boundary-guardrail]
  - glob: "dataplane/services/ds-dnsgate/**"
    tags: [boundary-conformance, boundary-guardrail, dns-rebinding]
  - glob: "docs/**"
    tags: []
  - glob: "guardrail-map.yaml"
    tags: [full-matrix]
"""


class _Fixture:
    """A temp dir holding a synthetic map + a changed-paths file."""

    def __init__(self, map_text, changed_lines):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.map = root / "guardrail-map.yaml"
        self.changed = root / "changed-paths.txt"
        self.out = root / "selected-tags.txt"
        self.map.write_text(map_text)
        self.changed.write_text("".join(ln + "\n" for ln in changed_lines))

    def select(self):
        # silence the trace
        return sel.select(str(self.map), str(self.changed), str(self.out), log=lambda *a, **k: None)

    def out_lines(self):
        return [ln for ln in self.out.read_text().splitlines() if ln]

    def cleanup(self):
        self._tmp.cleanup()


def run_select(map_text, changed_lines):
    fx = _Fixture(map_text, changed_lines)
    try:
        tags = fx.select()
        return tags, fx.out_lines()
    finally:
        fx.cleanup()


class TestGuardrailScopeSelect(unittest.TestCase):
    def test_unmapped_path_forces_full_matrix(self):
        """A path that matches NO glob fails closed to the full matrix."""
        tags, out = run_select(SYNTH_MAP, ["orchestrator/internal/newthing/foo.go"])
        self.assertEqual(tags, ["full-matrix"])
        self.assertEqual(out, ["full-matrix"])

    def test_meta_change_forces_full_matrix(self):
        """Editing guardrail-map.yaml itself is a full-matrix event (D47)."""
        tags, _ = run_select(SYNTH_MAP, ["guardrail-map.yaml"])
        self.assertEqual(tags, ["full-matrix"])

    def test_most_specific_glob_precedence(self):
        """A narrowing row (ds-dnsgate) wins over the broader dataplane row,
        and never weakens it — the more-specific tag set is what is selected."""
        tags, _ = run_select(
            SYNTH_MAP, ["dataplane/services/ds-dnsgate/src/txn.rs"]
        )
        self.assertEqual(
            tags, ["boundary-conformance", "boundary-guardrail", "dns-rebinding"]
        )

    def test_broad_glob_when_not_under_narrow(self):
        """A dataplane path NOT under the narrowing row picks the broad row."""
        tags, _ = run_select(SYNTH_MAP, ["dataplane/services/ds-tlsproxy/src/lib.rs"])
        self.assertEqual(tags, ["boundary-conformance", "boundary-guardrail"])

    def test_no_base_sentinel_forces_full_matrix(self):
        """The workflow's no-usable-base sentinel matches no glob => full matrix."""
        tags, _ = run_select(SYNTH_MAP, ["__no_base__/forces-full-matrix"])
        self.assertEqual(tags, ["full-matrix"])

    def test_empty_diff_sentinel_forces_full_matrix(self):
        """The workflow's empty-diff sentinel matches no glob => full matrix."""
        tags, _ = run_select(SYNTH_MAP, ["__empty_diff__/forces-full-matrix"])
        self.assertEqual(tags, ["full-matrix"])

    def test_empty_changed_set_selects_nothing(self):
        """An empty changed-paths file selects no tags (the workflow only feeds
        this when it has deliberately decided there is nothing to scope; the
        sentinels above are how a genuinely-empty diff still fails closed)."""
        tags, out = run_select(SYNTH_MAP, [])
        self.assertEqual(tags, [])
        self.assertEqual(out, [])

    def test_docs_mapped_to_no_guardrail_run(self):
        """A path mapped to an EMPTY tag list is 'no guardrail run', NOT
        unmapped — it must NOT force the full matrix."""
        tags, _ = run_select(SYNTH_MAP, ["docs/06-testing-and-assurance.md"])
        self.assertEqual(tags, [])

    def test_full_matrix_subsumes_narrower_tags(self):
        """When one diff selects both a narrow tag and full-matrix (via an
        unmapped path), the result collapses to just full-matrix."""
        tags, _ = run_select(
            SYNTH_MAP,
            ["dataplane/services/ds-dnsgate/src/txn.rs", "unmapped/tree/x.go"],
        )
        self.assertEqual(tags, ["full-matrix"])

    def test_default_unmapped_tag_collapses_to_full_matrix(self):
        """If a rule explicitly names the default.unmapped tag, the result still
        collapses to the single full-matrix selection (subsumption)."""
        tags, _ = run_select(SYNTH_MAP, ["guardrail-map.yaml"])
        self.assertEqual(tags, ["full-matrix"])

    def test_malformed_map_fails_closed(self):
        """A map with no default.unmapped is a fail-closed operator error: the
        selector exits 2 rather than silently scoping nothing."""
        bad_map = "version: 0\nrules:\n  - glob: \"x/**\"\n    tags: [t]\n"
        fx = _Fixture(bad_map, ["x/y.go"])
        try:
            with self.assertRaises(SystemExit) as cm:
                fx.select()
            self.assertEqual(cm.exception.code, 2)
        finally:
            fx.cleanup()

    def test_main_cli_writes_output(self):
        """The CLI entrypoint wires --map/--changed/--out and writes the file."""
        fx = _Fixture(SYNTH_MAP, ["unmapped/x.go"])
        try:
            rc = sel.main(
                ["--map", str(fx.map), "--changed", str(fx.changed), "--out", str(fx.out)]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(fx.out_lines(), ["full-matrix"])
        finally:
            fx.cleanup()


if __name__ == "__main__":
    unittest.main()
