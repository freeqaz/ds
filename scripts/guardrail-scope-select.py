#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""D47 guardrail-scope selector — fail-closed diff -> guardrail-tag selection.

Extracted verbatim (logic-identical) from the inline heredoc that lived in
.github/workflows/guardrail-scope.yml so the FAIL-CLOSED selection mechanism is
unit-testable (doc 06 §3c / §4; D47, doc 04 §6).  The workflow now invokes this
script instead of inlining the parse; the divergence-filing nightly backstop
(.github/workflows/guardrail-scope-nightly.yml) reuses the same selection.

What it does (doc 06 §3c, guardrail-map.yaml header):
  1. Parses the fixed guardrail-map.yaml shape: `default.unmapped: <tag>` plus a
     `rules:` list of {glob, tags}.  Stdlib only — no PyYAML dependency, because
     the map's shape is small and fixed.
  2. Matches each changed path against the globs, picking the MOST-SPECIFIC
     matching glob (D47 precedence: longest non-wildcard prefix wins, so a
     narrowing row never weakens a broader one).
  3. FAILS CLOSED: a changed path that matches NO glob selects the FULL guardrail
     matrix (`full-matrix`/`default.unmapped`).  The map is an optimization that
     narrows scope, never a safety requirement — forgetting to map a new tree
     costs CI time, not coverage.  A path explicitly mapped to an EMPTY tag list
     (e.g. docs/**) is "no guardrail run", which is NOT the same as unmapped.
  4. `full-matrix` (or any selection of the default.unmapped tag) subsumes every
     narrower tag.

Sentinels: the workflow feeds a synthetic path that matches no glob
(`__no_base__/...`, `__empty_diff__/...`) when there is no usable base ref or an
empty diff, which lands in the unmapped branch and forces the full matrix — so
the no-base / empty-diff cases are exercised through the same code path here.

Exit codes:
  0  — selection written (selected-tags.txt) and trace printed.
  2  — the map is malformed (no default.unmapped) — a fail-closed condition an
       operator must fix; the map itself failing to parse is never silently
       treated as "nothing to run".

Usage:
  guardrail-scope-select.py [--map MAP] [--changed CHANGED] [--out OUT]
Defaults match the workflow's working directory: MAP=guardrail-map.yaml,
CHANGED=changed-paths.txt, OUT=selected-tags.txt.
"""

import argparse
import fnmatch
import sys


def parse_map(path):
    """Minimal parse of the fixed guardrail-map.yaml shape:
       default.unmapped: <tag>
       rules: [ {glob: "...", tags: [..]}, ... ]
    """
    rules = []          # list of (glob, [tags])
    unmapped = None
    cur_glob = None
    in_rules = False
    in_default = False
    with open(path) as f:
        for raw in f:
            line = raw.rstrip("\n")
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s == "default:":
                in_default, in_rules = True, False
                continue
            if s == "rules:":
                in_rules, in_default = True, False
                continue
            if in_default and s.startswith("unmapped:"):
                unmapped = s.split(":", 1)[1].strip()
                continue
            if in_rules and s.startswith("- glob:"):
                cur_glob = s.split(":", 1)[1].strip().strip('"').strip("'")
                rules.append([cur_glob, []])
                continue
            if in_rules and s.startswith("tags:") and rules:
                tagstr = s.split(":", 1)[1].strip()
                tagstr = tagstr.strip("[]")
                tags = [t.strip() for t in tagstr.split(",") if t.strip()]
                rules[-1][1] = tags
                continue
    if unmapped is None:
        print(
            "FAIL-CLOSED: guardrail-map.yaml has no default.unmapped — refusing to scope",
            file=sys.stderr,
        )
        sys.exit(2)
    return rules, unmapped


def specificity(glob):
    # Most-specific = longest non-wildcard prefix, tie-broken by length.
    prefix = glob.split("*", 1)[0]
    return (len(prefix), len(glob))


def match_path(p, rules, unmapped):
    best = None  # (specificity, glob, tags)
    for glob, tags in rules:
        # fnmatch with '*' spanning '/' — our globs use '**' for recursion;
        # normalize '**' to '*' for fnmatch (which treats '*' greedily here).
        fnglob = glob.replace("**", "*")
        if (
            fnmatch.fnmatch(p, fnglob)
            or fnmatch.fnmatch(p, fnglob.rstrip("/") + "/*")
            or p == glob.rstrip("/*")
        ):
            sp = specificity(glob)
            if best is None or sp > best[0]:
                best = (sp, glob, tags)
    if best is None:
        # Unmapped => the full matrix (fail-closed). The empty list is a
        # mapped "no guardrail run" (e.g. docs/**), which is NOT unmapped.
        return [unmapped], True
    return best[2], False


def select(map_path, changed_path, out_path, log=print):
    """Run the selection. Returns the sorted list of selected tags.

    `log` is the trace sink (defaults to print); tests pass a collector to
    assert the trace, or `lambda *a, **k: None` to silence it.
    """
    rules, unmapped = parse_map(map_path)
    selected = set()
    forced_full = False
    with open(changed_path) as f:
        paths = [ln.strip() for ln in f if ln.strip()]
    for p in paths:
        tags, was_unmapped = match_path(p, rules, unmapped)
        if was_unmapped:
            forced_full = True
            log(f"  {p}: UNMAPPED -> full-matrix (fail-closed)")
        else:
            if tags:
                log(f"  {p}: tags={tags}")
            else:
                log(f"  {p}: mapped to NO guardrail run (e.g. docs)")
        for t in tags:
            selected.add(t)

    # full-matrix subsumes every narrower tag.
    if unmapped in selected or "full-matrix" in selected:
        selected = {"full-matrix"}

    ordered = sorted(selected)
    with open(out_path, "w") as out:
        for t in ordered:
            out.write(t + "\n")

    log("----- selected guardrail tags -----")
    log("\n".join(ordered) if ordered else "(none — no guardrail-bearing change)")
    return ordered


def main(argv=None):
    ap = argparse.ArgumentParser(description="D47 fail-closed guardrail-scope selector")
    ap.add_argument("--map", default="guardrail-map.yaml", help="path to guardrail-map.yaml")
    ap.add_argument("--changed", default="changed-paths.txt", help="newline-delimited changed paths")
    ap.add_argument("--out", default="selected-tags.txt", help="output: newline-delimited selected tags")
    args = ap.parse_args(argv)
    select(args.map, args.changed, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
