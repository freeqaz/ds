#!/usr/bin/env bun
// SPDX-License-Identifier: Apache-2.0
/**
 * loc-report — lines-of-code report for this repo, vendored/generated/data fluff removed.
 *
 * Two questions, one exclusion policy:
 *
 *   snapshot (default)   How much hand-written source lives in the tree *right now*,
 *                        broken down by language. Counts only git-tracked files
 *                        (so .gitignored build output / the live taskdb.sqlite never count).
 *   churn (--churn)      How many lines were *written* over git history (added / removed /
 *                        net), optionally grouped by author, language, or day.
 *
 * WHAT IS DROPPED (the "ignore vendored deps, json, and other fluff" rule):
 *   - vendored / third-party trees:  any vendor/ third_party/ node_modules/ dir
 *   - generated code:                proto/gen/, .pb.go, _pb2.py, _pb2_grpc.py, .pb.rs
 *   - test data & goldens:           any testdata/ fixtures/ golden(s)/ dir
 *   - build/scratch:                 .bin/ target/ dist/ build/
 *   - the taskdb store:              tasks/ (it is JSON state, not code)
 *   - lockfiles:                     Cargo.lock, go.sum, go.work.sum, *-lock.json, bun.lockb, …
 *   - data formats:                  .json, .ndjson, .csv, .wat/.wast, and any extension
 *                                    not recognized as code/docs/config (shown as one
 *                                    "other (excluded)" row so nothing is hidden).
 *
 * The headline number is the CODE bucket. DOCS and CONFIG are reported alongside but kept
 * out of the headline; pass --all to fold every text bucket into one grand total.
 *
 * Single-file Bun TypeScript, no external deps. Run: bun scripts/loc-report.ts [--churn] [...]
 */

import { parseArgs } from "node:util";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

// ─── Classification ───────────────────────────────────────────────────────────

type Bucket = "code" | "docs" | "config";

// extension (no dot, lowercased) → [language label, bucket]
const EXT: Record<string, [string, Bucket]> = {
  go: ["Go", "code"],
  rs: ["Rust", "code"],
  ts: ["TypeScript", "code"], tsx: ["TypeScript", "code"],
  js: ["JavaScript", "code"], jsx: ["JavaScript", "code"], mjs: ["JavaScript", "code"], cjs: ["JavaScript", "code"],
  py: ["Python", "code"],
  sh: ["Shell", "code"], bash: ["Shell", "code"], zsh: ["Shell", "code"],
  proto: ["Protobuf", "code"],
  sql: ["SQL", "code"],
  c: ["C", "code"], h: ["C", "code"], cc: ["C++", "code"], cpp: ["C++", "code"], hpp: ["C++", "code"], hh: ["C++", "code"],
  java: ["Java", "code"], kt: ["Kotlin", "code"], rb: ["Ruby", "code"], lua: ["Lua", "code"], pl: ["Perl", "code"],
  wit: ["WIT", "code"],

  md: ["Markdown", "docs"], markdown: ["Markdown", "docs"], rst: ["reST", "docs"], adoc: ["AsciiDoc", "docs"], txt: ["Text", "docs"],

  yaml: ["YAML", "config"], yml: ["YAML", "config"], toml: ["TOML", "config"],
  ini: ["INI", "config"], cfg: ["INI", "config"], conf: ["Conf", "config"], env: ["Env", "config"], mk: ["Make", "config"],
};

// extensionless files keyed by basename
const BASENAME: Record<string, [string, Bucket]> = {
  Makefile: ["Make", "config"], Dockerfile: ["Dockerfile", "config"],
  "go.mod": ["Go mod", "config"], "go.work": ["Go mod", "config"],
};

// Always-dropped path predicates. Order: cheapest first.
function isExcluded(p: string): boolean {
  if (/(^|\/)(vendor|third_party|node_modules)\//.test(p)) return true;
  if (p.startsWith("proto/gen/")) return true;
  if (/(^|\/)(testdata|fixtures|golden|goldens)\//.test(p)) return true;
  if (/(^|\/)(\.bin|target|dist|build)\//.test(p)) return true;
  if (p.startsWith("tasks/")) return true; // taskdb JSON state, not code
  if (/\.(pb\.go|pb\.rs)$/.test(p)) return true;
  if (/_pb2(_grpc)?\.py$/.test(p)) return true;
  const base = p.slice(p.lastIndexOf("/") + 1);
  if (/^(Cargo\.lock|go\.sum|go\.work\.sum|bun\.lockb|yarn\.lock|uv\.lock|poetry\.lock)$/.test(base)) return true;
  if (/-lock\.json$/.test(base) || base === "package-lock.json") return true;
  if (/\.lock$/.test(base)) return true;
  return false;
}

// Returns [language, bucket] for a kept path, or null if it is not a counted text type.
function classify(p: string, root: string): [string, Bucket] | null {
  const base = p.slice(p.lastIndexOf("/") + 1);
  if (BASENAME[base]) return BASENAME[base];
  const dot = base.lastIndexOf(".");
  if (dot > 0) {
    const ext = base.slice(dot + 1).toLowerCase();
    return EXT[ext] ?? null;
  }
  // extensionless: classify by shebang (cheap first-line read)
  try {
    const fd = fs.openSync(path.join(root, p), "r");
    const buf = Buffer.alloc(64);
    const n = fs.readSync(fd, buf, 0, 64, 0);
    fs.closeSync(fd);
    const head = buf.slice(0, n).toString("utf8");
    if (head.startsWith("#!")) {
      if (/\b(bash|sh|zsh)\b/.test(head)) return ["Shell", "code"];
      if (/python/.test(head)) return ["Python", "code"];
      if (/\bbun\b|node/.test(head)) return ["JavaScript", "code"];
      return ["Shell", "code"];
    }
  } catch { /* unreadable → not counted */ }
  return null;
}

// ─── git plumbing ───────────────────────────────────────────────────────────────

function git(args: string[], root: string): string {
  const r = spawnSync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 1 << 30 });
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${r.stderr?.trim() || r.status}`);
  }
  return r.stdout;
}

function gitRoot(): string {
  const r = spawnSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" });
  if (r.status !== 0) throw new Error("not inside a git repository");
  return r.stdout.trim();
}

function countLines(abs: string): number {
  let buf: Buffer;
  try { buf = fs.readFileSync(abs); } catch { return 0; }
  if (buf.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < buf.length; i++) if (buf[i] === 0x0a) n++;
  if (buf[buf.length - 1] !== 0x0a) n++; // unterminated last line
  return n;
}

// ─── formatting ──────────────────────────────────────────────────────────────

let COLOR = true;
const c = (code: string, s: string) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = (s: string) => c("1", s);
const dim = (s: string) => c("2", s);
const cyan = (s: string) => c("36", s);
const green = (s: string) => c("32", s);
const red = (s: string) => c("31", s);
const num = (n: number) => n.toLocaleString("en-US");

function table(headers: string[], rows: string[][], aligns: ("l" | "r")[]): string {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
  const pad = (s: string, w: number, a: "l" | "r") =>
    a === "r" ? s.padStart(w) : s.padEnd(w);
  const line = (cells: string[], style?: (s: string) => string) =>
    "  " + cells.map((cell, i) => {
      const p = pad(cell, widths[i], aligns[i]);
      return style ? style(p) : p;
    }).join("  ");
  const out = [line(headers, bold)];
  out.push("  " + widths.map((w) => "─".repeat(w)).join("  "));
  for (const r of rows) out.push(line(r));
  return out.join("\n");
}

// ─── snapshot ─────────────────────────────────────────────────────────────────

interface LangStat { lang: string; bucket: Bucket; files: number; lines: number }

function snapshot(root: string, opts: { all: boolean; showExcluded: boolean; json: boolean }) {
  const tracked = git(["ls-files", "-z"], root).split("\0").filter(Boolean);
  const byLang = new Map<string, LangStat>();
  let droppedFiles = 0;
  const droppedExt = new Map<string, number>();

  for (const p of tracked) {
    if (isExcluded(p)) { droppedFiles++; continue; }
    const cls = classify(p, root);
    if (!cls) {
      droppedFiles++;
      const base = p.slice(p.lastIndexOf("/") + 1);
      const dot = base.lastIndexOf(".");
      const key = dot > 0 ? "." + base.slice(dot + 1).toLowerCase() : "(no ext)";
      droppedExt.set(key, (droppedExt.get(key) ?? 0) + 1);
      continue;
    }
    const [lang, bucket] = cls;
    const lines = countLines(path.join(root, p));
    const cur = byLang.get(lang) ?? { lang, bucket, files: 0, lines: 0 };
    cur.files++; cur.lines += lines;
    byLang.set(lang, cur);
  }

  const stats = [...byLang.values()].sort((a, b) => b.lines - a.lines);
  const sum = (bk: Bucket) => stats.filter((s) => s.bucket === bk)
    .reduce((a, s) => ({ files: a.files + s.files, lines: a.lines + s.lines }), { files: 0, lines: 0 });
  const code = sum("code"), docs = sum("docs"), config = sum("config");

  if (opts.json) {
    console.log(JSON.stringify({
      languages: stats,
      totals: { code, docs, config },
      headline: opts.all ? {
        files: code.files + docs.files + config.files,
        lines: code.lines + docs.lines + config.lines,
      } : code,
      droppedFiles,
    }, null, 2));
    return;
  }

  const buckets: Bucket[] = opts.all ? ["code", "docs", "config"] : ["code"];
  const shown = stats.filter((s) => buckets.includes(s.bucket));
  const rows = shown.map((s) => [
    s.lang,
    opts.all ? s.bucket : "",
    num(s.files),
    num(s.lines),
  ].filter((_, i) => opts.all || i !== 1));

  console.log(bold(`\nLines of code — snapshot (git-tracked, fluff removed)\n`));
  const heads = opts.all ? ["Language", "Bucket", "Files", "Lines"] : ["Language", "Files", "Lines"];
  const al: ("l" | "r")[] = opts.all ? ["l", "l", "r", "r"] : ["l", "r", "r"];
  console.log(table(heads, rows, al));

  console.log();
  const head = (label: string, t: { files: number; lines: number }, style: (s: string) => string) =>
    console.log("  " + style(label.padEnd(22)) + style(num(t.lines).padStart(10) + " lines") + dim(`  (${num(t.files)} files)`));
  head("CODE", code, (s) => bold(green(s)));
  head("Docs", docs, dim);
  head("Config", config, dim);
  if (opts.all) {
    const tot = { files: code.files + docs.files + config.files, lines: code.lines + docs.lines + config.lines };
    head("TOTAL (code+docs+config)", tot, (s) => bold(cyan(s)));
  }
  console.log("  " + dim(`${num(droppedFiles)} files dropped as vendored/generated/data/fluff`));

  if (opts.showExcluded) {
    console.log(dim("\n  dropped non-code extensions (post path-filter):"));
    const ex = [...droppedExt.entries()].sort((a, b) => b[1] - a[1]).slice(0, 30);
    for (const [k, v] of ex) console.log(dim(`    ${k.padEnd(14)} ${num(v)}`));
  }
  console.log();
}

// ─── churn ───────────────────────────────────────────────────────────────────

function churn(root: string, opts: {
  since?: string; until?: string; author?: string;
  by: "total" | "author" | "lang" | "day"; json: boolean; all: boolean;
}) {
  const args = ["log", "--numstat", "--no-renames", "--no-merges",
    "--pretty=tformat:\x01%an\x01%ad", "--date=short"];
  if (opts.since) args.push(`--since=${opts.since}`);
  if (opts.until) args.push(`--until=${opts.until}`);
  if (opts.author) args.push(`--author=${opts.author}`);
  const out = git(args, root);

  // aggregate: key → {added, removed}
  const agg = new Map<string, { added: number; removed: number }>();
  const bump = (key: string, a: number, r: number) => {
    const cur = agg.get(key) ?? { added: 0, removed: 0 };
    cur.added += a; cur.removed += r; agg.set(key, cur);
  };
  let curAuthor = "", curDay = "";
  let totA = 0, totR = 0;
  const wantBuckets: Bucket[] = opts.all ? ["code", "docs", "config"] : ["code"];

  for (const raw of out.split("\n")) {
    if (raw.startsWith("\x01")) {
      const [, a, d] = raw.split("\x01");
      curAuthor = a ?? ""; curDay = d ?? "";
      continue;
    }
    if (!raw.trim()) continue;
    const m = raw.split("\t");
    if (m.length < 3) continue;
    const [addS, delS, file] = m;
    if (addS === "-" || delS === "-") continue; // binary
    if (isExcluded(file)) continue;
    const cls = classify(file, root);
    if (!cls || !wantBuckets.includes(cls[1])) continue;
    const added = parseInt(addS, 10) || 0;
    const removed = parseInt(delS, 10) || 0;
    totA += added; totR += removed;
    const key = opts.by === "author" ? curAuthor
      : opts.by === "day" ? curDay
      : opts.by === "lang" ? cls[0]
      : "total";
    bump(key, added, removed);
  }

  if (opts.json) {
    console.log(JSON.stringify({
      groupBy: opts.by, since: opts.since ?? null, until: opts.until ?? null,
      groups: [...agg.entries()].map(([k, v]) => ({ key: k, ...v, net: v.added - v.removed })),
      total: { added: totA, removed: totR, net: totA - totR },
    }, null, 2));
    return;
  }

  const scope = opts.all ? "code+docs+config" : "code";
  const win = [opts.since && `since ${opts.since}`, opts.until && `until ${opts.until}`, opts.author && `author ~/${opts.author}/`]
    .filter(Boolean).join(", ") || "all history";
  console.log(bold(`\nLines written — churn (${scope}; ${win})\n`));

  const rows = [...agg.entries()]
    .sort((a, b) => opts.by === "day" ? a[0].localeCompare(b[0]) : (b[1].added - b[1].removed) - (a[1].added - a[1].removed))
    .map(([k, v]) => [
      k || "(unknown)",
      green("+" + num(v.added)),
      red("-" + num(v.removed)),
      (v.added - v.removed >= 0 ? "+" : "") + num(v.added - v.removed),
    ]);

  if (opts.by !== "total") {
    const label = opts.by === "author" ? "Author" : opts.by === "lang" ? "Language" : "Day";
    console.log(table([label, "Added", "Removed", "Net"], rows, ["l", "r", "r", "r"]));
    console.log();
  }
  console.log("  " + bold("Total  ")
    + green("+" + num(totA)) + "  " + red("-" + num(totR))
    + "  net " + bold((totA - totR >= 0 ? "+" : "") + num(totA - totR)) + " lines\n");
}

// ─── main ────────────────────────────────────────────────────────────────────

const HELP = `
loc-report — lines of code in this repo, vendored/generated/data fluff removed.

Usage:
  bun scripts/loc-report.ts [options]            snapshot of tracked source by language
  bun scripts/loc-report.ts --churn [options]    lines added/removed over git history

Options:
  --churn            churn mode (lines written over history) instead of snapshot
  --by <k>           churn grouping: total | author | lang | day   (default: lang)
  --since <when>     churn: only commits after  (git date, e.g. 2026-06-01, "2 weeks ago")
  --until <when>     churn: only commits before
  --author <pat>     churn: restrict to commit author matching regex
  --all              fold docs + config into the totals (default: code only)
  --show-excluded    snapshot: list the non-code extensions that were dropped
  --json             machine-readable output
  --no-color         disable ANSI color
  -h, --help

Dropped everywhere: **/vendor, **/third_party, **/node_modules, proto/gen, **/testdata,
**/fixtures, **/golden(s), .bin/target/dist/build, tasks/ (taskdb), lockfiles, *.json and
any other non-code/doc/config extension.
`.trim();

function main() {
  let parsed;
  try {
    parsed = parseArgs({
      options: {
        churn: { type: "boolean", default: false },
        by: { type: "string", default: "lang" },
        since: { type: "string" },
        until: { type: "string" },
        author: { type: "string" },
        all: { type: "boolean", default: false },
        "show-excluded": { type: "boolean", default: false },
        json: { type: "boolean", default: false },
        "no-color": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
      allowPositionals: false,
    });
  } catch (e) {
    console.error(String((e as Error).message));
    console.error("\n" + HELP);
    process.exit(2);
  }
  const o = parsed.values;
  if (o.help) { console.log(HELP); return; }
  COLOR = !o["no-color"] && process.stdout.isTTY !== false;

  const root = gitRoot();
  if (o.churn) {
    const by = String(o.by);
    if (!["total", "author", "lang", "day"].includes(by)) {
      console.error(`--by must be one of: total, author, lang, day`); process.exit(2);
    }
    churn(root, {
      since: o.since, until: o.until, author: o.author,
      by: by as any, json: !!o.json, all: !!o.all,
    });
  } else {
    snapshot(root, { all: !!o.all, showExcluded: !!o["show-excluded"], json: !!o.json });
  }
}

main();
