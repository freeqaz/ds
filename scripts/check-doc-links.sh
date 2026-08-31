#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-doc-links.sh — relative-link and #fragment lint over docs/**/*.md
# and README.md.
#
# BEHAVIOUR
#   - Collects every inline markdown link  [text](url)  in every checked file.
#   - Skips external links (http://, https://, mailto:) entirely — no network.
#   - For relative file targets: asserts the file exists relative to the
#     linking document.
#   - For #fragment targets: computes GitHub-style heading slugs (lowercase,
#     spaces→hyphens, punctuation stripped, -N suffix for duplicates) plus
#     explicit <a name="..."> anchors, and asserts the fragment resolves.
#     Same-file #fragment links are checked against the linking file itself.
#   - Failure output: <linking-file>:<line>: link '<url>' — <reason>
#
# RATCHET
#   scripts/doc-links-allowlist.txt holds pre-existing failures (one entry per
#   line, matching the "<file>:<line>: link '<url>'" prefix).  Allowlisted
#   failures print as warnings; only NEW failures cause a non-zero exit.
#   Never silently widen the allowlist — add entries explicitly after auditing.
#
#   AUDIT-COMMENT-BLOCK GUARD
#   The allowlist's own header demands an audit comment above every entry.
#   This checker enforces that convention: each non-comment, non-blank entry
#   line MUST be immediately preceded by at least one '#' comment line (blank
#   lines do not count).  A bare, uncommented entry is itself a NEW failure
#   (exit 1) naming the offending line — independent of whether the linked
#   failure still exists — so the list cannot be silently re-widened.
#   Override the allowlist path with DS_DOC_LINKS_ALLOWLIST (default:
#   scripts/doc-links-allowlist.txt) — used to keep the unit tests hermetic.
#
# FILE ENUMERATION (tracked-only)
#   The set of linting targets is the git-tracked markdown under docs/ plus a
#   tracked README.md, enumerated via `git ls-files` from the repo root — NOT a
#   filesystem walk (rglob).  An untracked .md (a local scratch draft, a
#   parallel session's work-in-progress) is therefore invisible to the gate, so
#   a half-written draft with a broken link cannot fail another session's lint.
#   Once the same file is `git add`ed it is scanned like any other tracked doc.
#   Outside a git repo (the hermetic guard tests build a plain temp dir) the
#   enumeration falls back to a docs/ glob so the script still runs its link
#   pass.  Override the list with DS_DOC_LINKS_FILES (newline-separated, repo-
#   relative) to keep tests hermetic — mirrors SECRET_SCAN_FILES in
#   check-fixture-provenance.sh.
#
# EXIT CODES
#   0  all clear (or all failures are allowlisted)
#   1  one or more NEW (non-allowlisted) failures
#
# USAGE
#   bash scripts/check-doc-links.sh
#   bash scripts/check-doc-links.sh --verbose    # also print passing links

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="${DS_DOC_LINKS_ALLOWLIST:-${REPO_ROOT}/scripts/doc-links-allowlist.txt}"

VERBOSE=0
for arg in "$@"; do
  [[ "$arg" == "--verbose" ]] && VERBOSE=1
done

# ---------------------------------------------------------------------------
# Python worker — all link-checking logic lives here; bash only drives it.
# ---------------------------------------------------------------------------
python3 - "$REPO_ROOT" "$ALLOWLIST" "$VERBOSE" << 'PYEOF'
import os
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
allowlist_path = Path(sys.argv[2])
verbose = sys.argv[3] == "1"

# Load allowlist (strip comments and blank lines).
#
# Audit-comment-block guard: every non-comment, non-blank entry line MUST be
# immediately preceded by at least one '#' comment line (a blank line does NOT
# count as a comment).  A bare, uncommented entry is recorded as a NEW failure
# naming the offending allowlist line, so the list cannot be silently widened.
allowlisted = set()
allowlist_guard_failures = []  # (line_no, entry) for bare, uncommented entries
allowlist_rel = allowlist_path
try:
    allowlist_rel = allowlist_path.resolve().relative_to(repo_root)
except (OSError, ValueError):
    allowlist_rel = allowlist_path

if allowlist_path.exists():
    raw_lines = allowlist_path.read_text(encoding="utf-8").splitlines()
    for idx, raw in enumerate(raw_lines):
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        allowlisted.add(entry)
        # The line immediately above (idx-1) must be a '#' comment line.
        prev = raw_lines[idx - 1].strip() if idx > 0 else ""
        if not prev.startswith("#"):
            allowlist_guard_failures.append((idx + 1, entry))

# ------------------------------------------------------------------
# Slug computation — GitHub-style
# ------------------------------------------------------------------
def github_slug(heading_text: str) -> str:
    # Strip inline markdown: links → link text, bold/italic/code markers
    text = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', heading_text)
    text = re.sub(r'[*_`]', '', text)
    text = text.lower()
    text = text.replace(' ', '-')
    # Keep only word chars (letters, digits, _) and hyphens
    text = re.sub(r'[^\w-]', '', text)
    text = text.strip('-')
    return text


def get_file_anchors(filepath: Path) -> dict:
    """Return {slug: line_number} for all headings and <a name> anchors."""
    anchors: dict = {}
    slug_counts: dict = {}
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return anchors

    for i, line in enumerate(lines, 1):
        m = re.match(r'^(#{1,6})\s+(.*)', line)
        if m:
            slug = github_slug(m.group(2).strip())
            if slug in slug_counts:
                slug_counts[slug] += 1
                unique = f"{slug}-{slug_counts[slug]}"
            else:
                slug_counts[slug] = 0
                unique = slug
            anchors[unique] = i

        # Explicit HTML anchors: <a name="foo"> or <a name='foo'>
        for am in re.finditer(r'<a\s+name=["\']([^"\']+)["\']', line):
            anchors[am.group(1)] = i

    return anchors


# Cache of anchors per resolved file path
_anchor_cache: dict = {}

def anchors_for(filepath: Path) -> dict:
    key = str(filepath)
    if key not in _anchor_cache:
        _anchor_cache[key] = get_file_anchors(filepath)
    return _anchor_cache[key]


# ------------------------------------------------------------------
# Link extraction
# ------------------------------------------------------------------
_LINK_RE = re.compile(r'\[(?:[^\]]*)\]\(([^)]+)\)')

def get_links(filepath: Path):
    """Yield (line_number, url) for every inline link in the file."""
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for i, line in enumerate(lines, 1):
        for m in _LINK_RE.finditer(line):
            yield i, m.group(1)


# ------------------------------------------------------------------
# File collection — TRACKED-ONLY (git ls-files, not a filesystem walk)
# ------------------------------------------------------------------
# Enumerate the docs markdown plus README.md from git's index rather than
# rglob-ing the working tree.  Rationale: an untracked .md (a local scratch
# draft, or a parallel session's work-in-progress) must not be able to fail
# this gate — only files that are actually committed/staged are linted.  This
# closes the cross-session footgun class shared by the other tracked-only
# checkers (check-spdx.sh, check-fixture-provenance.sh).
import subprocess

def _tracked_md_files():
    """Repo-relative POSIX paths for tracked docs/**.md + README.md.

    Precedence:
      1. DS_DOC_LINKS_FILES env override (newline-separated, repo-relative) —
         keeps the hermetic unit tests independent of any real git index.
      2. `git ls-files` from the repo root (the production path).
      3. A docs/ glob fallback, used only when the repo_root is not inside a
         git work tree (e.g. the guard tests' plain temp dir), so the script
         still runs its link pass there.
    """
    override = os.environ.get("DS_DOC_LINKS_FILES")
    if override is not None:
        return [p for p in (ln.strip() for ln in override.splitlines()) if p]

    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--", "docs", "README.md"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            text=True,
        ).stdout
        return [p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        # Not a git work tree (or git unavailable): fall back to a glob so the
        # script is still runnable outside a checkout.
        rels = []
        docs_root = repo_root / "docs"
        for p in docs_root.rglob("*.md"):
            rels.append(p.relative_to(repo_root).as_posix())
        if (repo_root / "README.md").exists():
            rels.append("README.md")
        return rels


# Keep only markdown targets (the ls-files pathspec already scopes to docs/ +
# README.md, but README itself could in principle be a non-.md; require .md or
# the explicit README.md to stay faithful to the original target set), then
# materialise absolute, deterministic-ordered paths.
_rel_md = [
    rel
    for rel in _tracked_md_files()
    if rel.endswith(".md")
]
docs_md = sorted(rel for rel in _rel_md if rel == "docs" or rel.startswith("docs/"))
readme_md = [rel for rel in _rel_md if rel == "README.md"]
md_files = [repo_root / rel for rel in (readme_md + docs_md)]

# ------------------------------------------------------------------
# Main lint pass
# ------------------------------------------------------------------
new_failures = []
warn_allowlisted = []

# Audit-comment-block guard failures surface as NEW failures (exit 1).
for guard_line, guard_entry in allowlist_guard_failures:
    new_failures.append(
        f"FAIL  {allowlist_rel}:{guard_line}: bare allowlist entry '{guard_entry}' "
        f"— missing required audit comment ('#' line) immediately above"
    )

for md_file in md_files:
    if not md_file.exists():
        continue

    for line_no, url in get_links(md_file):
        # Skip external links
        if url.startswith(("http://", "https://", "mailto:")):
            if verbose:
                rel = md_file.relative_to(repo_root)
                print(f"  skip external  {rel}:{line_no}: {url}")
            continue

        # Split into file portion and fragment portion
        if "#" in url:
            file_part, fragment = url.split("#", 1)
        else:
            file_part = url
            fragment = None

        # Resolve target file
        if file_part:
            target = (md_file.parent / file_part).resolve()
        else:
            target = md_file.resolve()

        rel_md = md_file.relative_to(repo_root)

        # Canonicalise a short key for allowlist matching:
        #   "<relative-linking-file>:<line>: link '<url>'"
        key = f"{rel_md}:{line_no}: link '{url}'"

        if file_part and not target.exists():
            reason = f"file not found: {file_part}"
            if key in allowlisted:
                warn_allowlisted.append(f"ALLOWLISTED  {rel_md}:{line_no}: link '{url}' — {reason}")
            else:
                new_failures.append(f"FAIL  {rel_md}:{line_no}: link '{url}' — {reason}")
            continue

        if fragment is not None:
            file_anchors = anchors_for(target)
            if fragment not in file_anchors:
                reason = f"fragment #{fragment} not found in {target.relative_to(repo_root)}"
                if key in allowlisted:
                    warn_allowlisted.append(f"ALLOWLISTED  {rel_md}:{line_no}: link '{url}' — {reason}")
                else:
                    new_failures.append(f"FAIL  {rel_md}:{line_no}: link '{url}' — {reason}")
                continue

        if verbose:
            print(f"  ok  {rel_md}:{line_no}: {url}")

# ------------------------------------------------------------------
# Report
# ------------------------------------------------------------------
for w in warn_allowlisted:
    print(f"WARNING: {w}", file=sys.stderr)

if new_failures:
    print(f"\ncheck-doc-links: {len(new_failures)} new failure(s):", file=sys.stderr)
    for f in new_failures:
        print(f"  {f}", file=sys.stderr)
    sys.exit(1)

total_warn = len(warn_allowlisted)
if total_warn:
    print(
        f"check-doc-links: OK ({total_warn} pre-existing failure(s) suppressed by allowlist)",
        file=sys.stderr,
    )
else:
    print("check-doc-links: all relative links and fragments resolved", file=sys.stderr)

sys.exit(0)
PYEOF
