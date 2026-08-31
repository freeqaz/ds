#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for vcs_meta_poller — the D74 vcs-family staleness guard.

Stdlib unittest only. No network: every test loads the synthetic fixtures and
mutates in-memory copies to drive the drift scenarios. The live-fetch path
(DS_META_POLLER_LIVE=1) is a deferred-manual step and is asserted only at the
guard layer (it refuses to touch the network off the env gate).
"""

from __future__ import annotations

import copy
import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

import vcs_meta_poller as poller

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
META_FIXTURE = os.path.join(FIXTURES, "github-meta.json")
PACK_FIXTURE = os.path.join(FIXTURES, "baseline-pack.synthetic.json")


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class FixtureSanityTest(unittest.TestCase):
    """The shipped fixtures are well-formed and mirror each other (no-drift base)."""

    def test_meta_fixture_is_labeled_synthetic(self):
        meta = load_json(META_FIXTURE)
        self.assertIn("_fixture", meta)
        self.assertIn("SYNTHETIC", meta["_fixture"])

    def test_pack_fixture_is_labeled_synthetic(self):
        pack = load_json(PACK_FIXTURE)
        self.assertIn("_fixture", pack)
        self.assertIn("SYNTHETIC", pack["_fixture"])

    def test_fixture_mirrors_pack_for_empty_diff(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        diff = poller.diff_meta(pack, meta)
        self.assertFalse(diff.has_drift, msg=f"unexpected drift: {diff}")
        self.assertEqual(diff.added, [])
        self.assertEqual(diff.rejected_wildcards, [])
        self.assertEqual(diff.pack_only, [])


class PackReadingTest(unittest.TestCase):
    def setUp(self):
        self.pack = load_json(PACK_FIXTURE)

    def test_vcs_fqdns_are_the_eight_documented_hosts(self):
        fqdns = poller.pack_vcs_fqdns(self.pack)
        self.assertEqual(
            fqdns,
            {
                "github.com",
                "api.github.com",
                "codeload.github.com",
                "raw.githubusercontent.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
                "github-releases.githubusercontent.com",
                "github-registry-files.githubusercontent.com",
            },
        )

    def test_core_entries_excluded_from_vcs_set(self):
        self.assertNotIn("api.anthropic.com", poller.pack_vcs_fqdns(self.pack))

    def test_machine_source_resolves_to_meta(self):
        self.assertEqual(
            poller.resolve_machine_source(self.pack), poller.GITHUB_META_SOURCE
        )


class MissingMachineSourceTest(unittest.TestCase):
    def test_all_null_machine_source_is_hard_error(self):
        pack = load_json(PACK_FIXTURE)
        for e in pack["baseline_pack"]["entries"]:
            e["machine_source"] = None
        pack["baseline_pack"].pop("machine_source", None)
        with self.assertRaises(poller.PollerError) as ctx:
            poller.resolve_machine_source(pack)
        self.assertIn("machine_source", str(ctx.exception))
        self.assertIn("refusing to guess", str(ctx.exception))

    def test_no_vcs_entries_is_hard_error(self):
        pack = {"baseline_pack": {"entries": [{"fqdn": "x", "family": "core"}]}}
        with self.assertRaises(poller.PollerError):
            poller.resolve_machine_source(pack)

    def test_conflicting_sources_rejected(self):
        pack = load_json(PACK_FIXTURE)
        pack["baseline_pack"]["entries"][1]["machine_source"] = "other.example/meta"
        with self.assertRaises(poller.PollerError) as ctx:
            poller.resolve_machine_source(pack)
        self.assertIn("conflicting", str(ctx.exception))

    def test_family_level_machine_source_is_honored(self):
        pack = load_json(PACK_FIXTURE)
        for e in pack["baseline_pack"]["entries"]:
            e.pop("machine_source", None)
        pack["baseline_pack"]["machine_source"] = "api.github.com/meta"
        self.assertEqual(
            poller.resolve_machine_source(pack), "api.github.com/meta"
        )


class MetaReadingTest(unittest.TestCase):
    def setUp(self):
        self.meta = load_json(META_FIXTURE)

    def test_ip_arrays_are_ignored(self):
        # Every top-level IP array value must be absent from the domain set.
        domains = set(poller.meta_domains(self.meta))
        for key in ("hooks", "web", "api", "git", "packages", "actions"):
            for cidr in self.meta.get(key, []):
                self.assertNotIn(cidr, domains)
        # The domain set is exactly the documented vcs hosts (no IPs leaked in).
        self.assertTrue(all("/" not in d for d in domains))

    def test_missing_domains_object_is_hard_error(self):
        meta = copy.deepcopy(self.meta)
        del meta["domains"]
        with self.assertRaises(poller.PollerError) as ctx:
            poller.meta_domains(meta)
        self.assertIn("domains", str(ctx.exception))

    def test_non_list_domain_service_is_hard_error(self):
        meta = copy.deepcopy(self.meta)
        meta["domains"]["broken"] = {"not": "a list"}
        with self.assertRaises(poller.PollerError):
            poller.meta_domains(meta)


class AddedDomainTest(unittest.TestCase):
    def test_new_exact_fqdn_is_proposed(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        meta["domains"]["website"].append("new-vcs.githubusercontent.com")
        diff = poller.diff_meta(pack, meta)
        self.assertTrue(diff.has_drift)
        self.assertEqual(diff.added, ["new-vcs.githubusercontent.com"])
        self.assertEqual(diff.rejected_wildcards, [])
        self.assertEqual(diff.pack_only, [])

    def test_added_fqdn_appears_in_unified_diff(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        meta["domains"]["website"].append("new-vcs.githubusercontent.com")
        diff = poller.diff_meta(pack, meta)
        ud = poller.render_unified_diff(diff, pack)
        self.assertIn("+new-vcs.githubusercontent.com", ud)
        self.assertIn("(current)", ud)
        self.assertIn("(proposed)", ud)

    def test_added_fqdn_in_pr_body_marked_proposal(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        meta["domains"]["website"].append("new-vcs.githubusercontent.com")
        diff = poller.diff_meta(pack, meta)
        body = poller.render_pr_body(diff)
        self.assertIn("new-vcs.githubusercontent.com", body)
        self.assertIn("proposal for human review", body.lower())
        self.assertIn("auto-applied", body.lower())
        self.assertIn("never auto-promoted", body.lower())


class RemovedDomainTest(unittest.TestCase):
    def test_pack_only_fqdn_surfaced_for_review(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        # /meta drops a host the pack still authorizes (the statsig-style signal).
        meta["domains"]["website"] = [
            d
            for d in meta["domains"]["website"]
            if d != "codeload.github.com"
        ]
        diff = poller.diff_meta(pack, meta)
        self.assertTrue(diff.has_drift)
        self.assertIn("codeload.github.com", diff.pack_only)
        self.assertEqual(diff.added, [])
        # Never auto-removed: the unified diff keeps it (after == before for pack).
        ud = poller.render_unified_diff(diff, pack)
        self.assertNotIn("-codeload.github.com", ud)


class WildcardRejectionTest(unittest.TestCase):
    def test_host_wide_wildcard_reported_never_proposed(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        meta["domains"]["website"].append("*.githubusercontent.com")
        diff = poller.diff_meta(pack, meta)
        self.assertTrue(diff.has_drift)
        self.assertEqual(diff.rejected_wildcards, ["*.githubusercontent.com"])
        # Crucially: a wildcard is NEVER added to the proposed FQDN set.
        self.assertNotIn("*.githubusercontent.com", diff.added)
        ud = poller.render_unified_diff(diff, pack)
        self.assertNotIn("+*.githubusercontent.com", ud)

    def test_wildcard_in_pr_body_is_flagged_not_proposed(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        meta["domains"]["website"].append("*.githubusercontent.com")
        diff = poller.diff_meta(pack, meta)
        body = poller.render_pr_body(diff)
        self.assertIn("NOT proposed", body)
        self.assertIn("*.githubusercontent.com", body)

    def test_is_wildcard_classifier(self):
        self.assertTrue(poller.is_wildcard("*.githubusercontent.com"))
        self.assertTrue(poller.is_wildcard("*.core.windows.net"))
        self.assertFalse(poller.is_wildcard("github.com"))


class NoDriftTest(unittest.TestCase):
    def test_empty_diff_when_fixture_mirrors_pack(self):
        pack = load_json(PACK_FIXTURE)
        meta = load_json(META_FIXTURE)
        diff = poller.diff_meta(pack, meta)
        self.assertFalse(diff.has_drift)
        body = poller.render_pr_body(diff)
        self.assertIn("No drift", body)

    def test_run_exits_zero_no_drift(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = poller.run(["--pack", PACK_FIXTURE, "--fixture", META_FIXTURE])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "")  # no proposal emitted
        self.assertIn("no drift", err.getvalue().lower())


class LiveFetchGateTest(unittest.TestCase):
    def test_live_fetch_refuses_without_env_gate(self):
        # Ensure the gate is off, then assert the guard refuses (no network).
        prior = os.environ.pop(poller.LIVE_ENV, None)
        try:
            with self.assertRaises(poller.PollerError) as ctx:
                poller.fetch_meta_live()
            self.assertIn(poller.LIVE_ENV, str(ctx.exception))
        finally:
            if prior is not None:
                os.environ[poller.LIVE_ENV] = prior

    def test_default_path_without_fixture_refuses_network(self):
        prior = os.environ.pop(poller.LIVE_ENV, None)
        try:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = poller.run(["--pack", PACK_FIXTURE])
            self.assertEqual(rc, 2)
            self.assertIn("refusing to touch the network", err.getvalue())
        finally:
            if prior is not None:
                os.environ[poller.LIVE_ENV] = prior


class CliDriftExitTest(unittest.TestCase):
    def test_run_exits_one_and_emits_proposal_on_drift(self):
        # Write a drifted meta doc to a temp file the CLI can read.
        import tempfile

        meta = load_json(META_FIXTURE)
        meta["domains"]["website"].append("new-vcs.githubusercontent.com")
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(meta, tf)
            tmp = tf.name
        try:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = poller.run(["--pack", PACK_FIXTURE, "--fixture", tmp])
            self.assertEqual(rc, 1)
            stdout = out.getvalue()
            self.assertIn("+new-vcs.githubusercontent.com", stdout)
            self.assertIn("Proposed vcs-family pack update", stdout)
        finally:
            os.unlink(tmp)

    def test_pack_read_only_unchanged_after_run(self):
        before = load_json(PACK_FIXTURE)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            poller.run(["--pack", PACK_FIXTURE, "--fixture", META_FIXTURE])
        after = load_json(PACK_FIXTURE)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
