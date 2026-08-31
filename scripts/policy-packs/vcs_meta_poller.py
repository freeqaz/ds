#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vcs_meta_poller — D74 vcs-family staleness guard for the baseline policy pack.

WHAT THIS IS (and is not)
-------------------------
A *proposal generator*. It reads the vcs-family entries of the shipped D64/D74
baseline policy pack (read-only — it NEVER writes the pack), fetches GitHub's
machine-readable endpoint source (``api.github.com/meta`` → the ``domains``
object), diffs the two honoring D74 wildcard policy, and emits a unified diff
plus a PR-body markdown stub for a HUMAN to review. Nothing here is ever
auto-applied: per docs/13 §3 and D74's three-stage promotion rule, an
out-of-family or wildcard candidate lands in a human review queue and is never
auto-promoted (``dataplane/artifacts/policy-packs/README.md`` "Poller contract").

The staleness lesson it guards against is named in the pack README and doc 13
§3: ``statsig.anthropic.com`` sat in Anthropic's own firewall script while
NXDOMAIN. A daily diff against the vendor's own machine source catches the
inverse — the vendor adds a domain the pack has not yet authorized.

WIRE SHAPE (documented, not invented)
-------------------------------------
``api.github.com/meta`` returns a JSON object. The top level carries
IP/CIDR arrays per service (``hooks``, ``web``, ``api``, ``git``,
``packages``, ``actions`` …) — these are **diagnostics only and are NEVER used
for authorization** (doc 13 §3 vcs row). The machine-readable *domain* source
is the ``domains`` object, whose values are arrays of FQDN / wildcard strings
keyed by service (``domains.website``, ``domains.codespaces``,
``domains.copilot`` …). This poller reads ONLY ``domains``; it explicitly
ignores every top-level IP array.

PACK SHAPE
----------
The shipped pack is YAML (doc 13 §3 ``baseline_pack``); the stdlib has no YAML
parser and this tool is stdlib-only, so it consumes a JSON projection of the
pack's ``baseline_pack`` object (a strict subset of YAML — see the README
"Poller contract" for the yaml→json projection step when the YAML pack lands).
It needs exactly two things from that object:

  * ``baseline_pack.entries[]`` — for every entry with ``family == "vcs"``,
    its ``fqdn`` (the authorized FQDN set).
  * ``baseline_pack.machine_source`` *or* per-entry ``machine_source`` — the
    poll target. For the vcs family this is ``api.github.com/meta``. An entry
    whose ``machine_source`` is ``null`` (e.g. core entries point at a doc
    page, not /meta) is not pollable; if NO vcs entry carries a machine_source
    the poller errors (missing machine_source is a hard error, never a guess).

LIVE FETCH
----------
By default the /meta document is loaded from ``--fixture`` (a saved synthetic
or captured response). Live fetch is gated behind ``DS_META_POLLER_LIVE=1`` and
is a DEFERRED MANUAL step: a failed live lookup is a HARD ERROR (raises), never
a guess — a poller that guesses a vendor domain list is worse than one that
fails loudly (the statsig lesson again).

Usage::

    # default: diff the synthetic fixture against the pack (no network)
    vcs_meta_poller.py --pack pack.json --fixture fixtures/github-meta.json

    # deferred manual: live fetch (opt-in, network)
    DS_META_POLLER_LIVE=1 vcs_meta_poller.py --pack pack.json

Exit status: 0 = no drift; 1 = drift found (a proposal was emitted); 2 = error.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable

VCS_FAMILY = "vcs"
GITHUB_META_URL = "https://api.github.com/meta"
# The /meta machine source string as it appears in the pack (host + path, no scheme).
GITHUB_META_SOURCE = "api.github.com/meta"

# Env gate for the deferred-manual live fetch path.
LIVE_ENV = "DS_META_POLLER_LIVE"


class PollerError(Exception):
    """A hard error: a failed lookup or a missing required field. Never a guess."""


# ── pack reading (read-only) ────────────────────────────────────────────────


def load_pack(path: str) -> dict:
    """Load the JSON projection of the baseline pack. Read-only."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PollerError(f"cannot read pack {path!r}: {exc}") from exc
    if not isinstance(doc, dict):
        raise PollerError(f"pack {path!r} is not a JSON object")
    return doc


def _baseline_pack(pack: dict) -> dict:
    bp = pack.get("baseline_pack", pack)
    if not isinstance(bp, dict):
        raise PollerError("pack has no baseline_pack object")
    return bp


def vcs_entries(pack: dict) -> list[dict]:
    """Return the pack's vcs-family entries (each a dict with at least fqdn)."""
    bp = _baseline_pack(pack)
    entries = bp.get("entries")
    if not isinstance(entries, list):
        raise PollerError("baseline_pack.entries is missing or not a list")
    out: list[dict] = []
    for e in entries:
        if isinstance(e, dict) and e.get("family") == VCS_FAMILY:
            out.append(e)
    return out


def pack_vcs_fqdns(pack: dict) -> set[str]:
    """The exact FQDNs the pack currently authorizes for the vcs family."""
    fqdns: set[str] = set()
    for e in vcs_entries(pack):
        fqdn = e.get("fqdn")
        if isinstance(fqdn, str) and fqdn:
            fqdns.add(fqdn.strip().lower())
    return fqdns


def resolve_machine_source(pack: dict) -> str:
    """The vcs-family poll target.

    Honors a family-level ``baseline_pack.machine_source`` and per-entry
    ``machine_source`` (entry-level wins where present). A null/absent source on
    EVERY vcs entry — with no family-level source either — is a HARD ERROR: the
    poller refuses to guess where to poll (missing machine_source error).
    """
    bp = _baseline_pack(pack)
    sources: set[str] = set()

    family_src = bp.get("machine_source")
    if isinstance(family_src, str) and family_src.strip():
        sources.add(family_src.strip())

    saw_vcs_entry = False
    for e in vcs_entries(pack):
        saw_vcs_entry = True
        src = e.get("machine_source")
        if isinstance(src, str) and src.strip():
            sources.add(src.strip())

    if not saw_vcs_entry:
        raise PollerError("pack has no vcs-family entries to poll")
    if not sources:
        raise PollerError(
            "no machine_source for the vcs family: every vcs entry has "
            "machine_source: null and baseline_pack.machine_source is unset — "
            "refusing to guess the poll target"
        )
    if len(sources) > 1:
        raise PollerError(
            f"conflicting machine_source values for vcs family: {sorted(sources)!r}"
        )
    return sources.pop()


# ── /meta reading ───────────────────────────────────────────────────────────


def load_meta_fixture(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PollerError(f"cannot read /meta fixture {path!r}: {exc}") from exc
    if not isinstance(doc, dict):
        raise PollerError(f"/meta fixture {path!r} is not a JSON object")
    return doc


def fetch_meta_live(url: str = GITHUB_META_URL, timeout: float = 15.0) -> dict:
    """Deferred-manual live fetch. A failed lookup is a HARD ERROR, never a guess."""
    if os.environ.get(LIVE_ENV) != "1":
        raise PollerError(
            f"live fetch requested without {LIVE_ENV}=1 — refusing to touch the "
            f"network on a default path"
        )
    req = urllib.request.Request(  # noqa: S310 - https URL, env-gated, deferred manual
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ds-vcs-meta-poller",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read()
        doc = json.loads(raw)
    except Exception as exc:  # network, TLS, JSON — all hard errors
        raise PollerError(f"live /meta fetch failed for {url!r}: {exc}") from exc
    if not isinstance(doc, dict):
        raise PollerError(f"live /meta response from {url!r} is not a JSON object")
    return doc


def meta_domains(meta: dict) -> list[str]:
    """Every domain string in the /meta ``domains`` object.

    Explicitly ignores every top-level IP array (``hooks``, ``web``, ``api``,
    ``git``, ``packages`` …) — those are diagnostics only and are NEVER used for
    authorization (doc 13 §3, D74). Only ``domains`` (an object of
    service → [domain …]) is consulted.
    """
    domains = meta.get("domains")
    if domains is None:
        raise PollerError(
            "/meta document has no 'domains' object — refusing to derive "
            "authorization from IP arrays"
        )
    if not isinstance(domains, dict):
        raise PollerError("/meta 'domains' is not an object")
    out: list[str] = []
    for service, values in domains.items():
        if not isinstance(values, list):
            raise PollerError(
                f"/meta domains.{service} is not a list of domain strings"
            )
        for v in values:
            if isinstance(v, str) and v.strip():
                out.append(v.strip().lower())
    return out


# ── D74 wildcard policy ─────────────────────────────────────────────────────


def is_wildcard(domain: str) -> bool:
    """A domain GitHub publishes as a wildcard (host-wide or leading ``*.``).

    Any ``*`` anywhere makes it a wildcard: a leading ``*.`` and a bare ``*``
    are both subsumed by this test, so exact-FQDN-only policy (D74) rejects the
    whole class with a single check.
    """
    return "*" in domain


# ── diff model ──────────────────────────────────────────────────────────────


@dataclass
class MetaDiff:
    """The result of diffing /meta domains against the pack's vcs FQDNs."""

    machine_source: str
    added: list[str] = field(default_factory=list)  # exact FQDNs to PROPOSE
    rejected_wildcards: list[str] = field(default_factory=list)  # reported, never proposed
    pack_only: list[str] = field(default_factory=list)  # in pack, not in /meta domains

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.rejected_wildcards or self.pack_only)


def diff_meta(pack: dict, meta: dict) -> MetaDiff:
    """Diff the /meta ``domains`` set against the pack's vcs FQDNs (D74 policy)."""
    source = resolve_machine_source(pack)
    pack_fqdns = pack_vcs_fqdns(pack)
    meta_doms = meta_domains(meta)

    # de-dupe while preserving determinism via sorting later
    meta_exact: set[str] = set()
    meta_wild: set[str] = set()
    for d in meta_doms:
        (meta_wild if is_wildcard(d) else meta_exact).add(d)

    # Exact FQDNs the vendor publishes that the pack does not yet authorize.
    added = sorted(meta_exact - pack_fqdns)
    # Wildcards present in /meta that are absent from the pack as exact FQDNs:
    # REPORTED for human attention, NEVER proposed (host-wide wildcards rejected,
    # doc 13 §3 / D74). A wildcard whose literal string already sits in the pack
    # (vendor-published + vendor-exclusive) is not flagged.
    rejected = sorted(w for w in meta_wild if w not in pack_fqdns)
    # FQDNs the pack authorizes that no longer appear in /meta domains — a
    # candidate-stale signal surfaced for human review (e.g. a renamed host).
    # Wildcards intentionally not subtracted from the exact comparison here.
    pack_only = sorted(pack_fqdns - meta_exact - meta_wild)

    return MetaDiff(
        machine_source=source,
        added=added,
        rejected_wildcards=rejected,
        pack_only=pack_only,
    )


# ── proposal rendering ──────────────────────────────────────────────────────


def render_unified_diff(diff: MetaDiff, pack: dict) -> str:
    """A deterministic unified diff of the authorized vcs FQDN list."""
    before = sorted(pack_vcs_fqdns(pack))
    after = sorted(set(before) | set(diff.added))  # wildcards never enter `after`
    lines = difflib.unified_diff(
        [f"{x}\n" for x in before],
        [f"{x}\n" for x in after],
        fromfile="pack/vcs.fqdns (current)",
        tofile="pack/vcs.fqdns (proposed)",
        n=3,
    )
    return "".join(lines)


def render_pr_body(diff: MetaDiff) -> str:
    """Human-review PR body markdown. A PROPOSAL — never auto-applied."""
    out: list[str] = []
    out.append("## Proposed vcs-family pack update (D74 staleness guard)")
    out.append("")
    out.append(
        f"`{diff.machine_source}` (the `domains` object) diverged from the "
        f"shipped baseline pack's vcs FQDNs. **This is a proposal for human "
        f"review — nothing here is auto-applied** (D74 three-stage promotion: "
        f"out-of-family / wildcard candidates land in the review queue, never "
        f"auto-promoted)."
    )
    out.append("")
    if diff.added:
        out.append("### Add (exact FQDNs the vendor now publishes)")
        for d in diff.added:
            out.append(f"- `{d}` — classify into the vcs family before merge.")
        out.append("")
    if diff.rejected_wildcards:
        out.append("### Reported wildcards (NOT proposed — host-wide rejected)")
        for d in diff.rejected_wildcards:
            out.append(
                f"- `{d}` — wildcard in /meta; exact FQDNs only (doc 13 §3 / "
                f"D74). A human decides whether a vendor-published, "
                f"vendor-exclusive narrowing is warranted."
            )
        out.append("")
    if diff.pack_only:
        out.append("### Pack-only (no longer in /meta `domains` — review for staleness)")
        for d in diff.pack_only:
            out.append(
                f"- `{d}` — present in the pack, absent from /meta. Could be a "
                f"renamed/retired host (the statsig lesson). Human review only; "
                f"never auto-removed."
            )
        out.append("")
    if not diff.has_drift:
        out.append("_No drift: the pack already authorizes every /meta vcs domain._")
        out.append("")
    out.append("> IP arrays from /meta are ignored by design — diagnostics only, "
               "never authorization (doc 13 §3).")
    return "\n".join(out) + "\n"


# ── CLI ─────────────────────────────────────────────────────────────────────


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vcs_meta_poller",
        description=(
            "D74 vcs-family staleness guard: diff api.github.com/meta domains "
            "against the baseline pack and emit a human-review PROPOSAL. Never "
            "auto-applies."
        ),
    )
    p.add_argument(
        "--pack",
        required=True,
        help="path to the JSON projection of the baseline pack (read-only)",
    )
    p.add_argument(
        "--fixture",
        default=None,
        help="path to a saved /meta JSON document (default source unless "
        f"{LIVE_ENV}=1)",
    )
    p.add_argument(
        "--format",
        choices=("diff", "pr-body", "both"),
        default="both",
        help="what to print on drift (default: both)",
    )
    return p


def load_meta(args: argparse.Namespace) -> dict:
    """Choose the /meta source: fixture by default, live only under the env gate."""
    if os.environ.get(LIVE_ENV) == "1":
        return fetch_meta_live()
    if not args.fixture:
        raise PollerError(
            f"no --fixture given and {LIVE_ENV} is not 1 — refusing to touch the "
            f"network on a default path. Pass --fixture, or set {LIVE_ENV}=1 for "
            f"the deferred-manual live fetch."
        )
    return load_meta_fixture(args.fixture)


def run(argv: Iterable[str] | None = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    try:
        pack = load_pack(args.pack)
        meta = load_meta(args)
        diff = diff_meta(pack, meta)
    except PollerError as exc:
        print(f"vcs_meta_poller: error: {exc}", file=sys.stderr)
        return 2

    if not diff.has_drift:
        # Explicit empty-diff no-op: fixture mirrors the pack.
        print(
            f"vcs_meta_poller: no drift — pack authorizes every {diff.machine_source} "
            f"vcs domain.",
            file=sys.stderr,
        )
        return 0

    if args.format in ("diff", "both"):
        sys.stdout.write(render_unified_diff(diff, pack))
    if args.format == "both":
        sys.stdout.write("\n")
    if args.format in ("pr-body", "both"):
        sys.stdout.write(render_pr_body(diff))
    return 1


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
