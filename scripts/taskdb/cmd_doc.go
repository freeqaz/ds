// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The doc family is the queryable face of the Markdown wiki: docs/*.md on disk
// stay the only truth, the DB is a derived index rebuilt by `doc sync`. search
// and get run an implicit incremental sync first (hash compare is cheap) so a
// result can never be stale without hooks or daemons (docs/22 §3, §8).
func cmdDoc(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb doc <sync|search|get|link|embed>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "sync":
		return docSync(db, rest)
	case "search":
		return docSearch(db, rest)
	case "get":
		return docGet(db, rest)
	case "link":
		return docLink(db, rest)
	case "embed":
		return docEmbed(db, rest)
	default:
		return fmt.Errorf("unknown doc subcommand: %s", sub)
	}
}

// docSyncResult is the tally a sync returns: added/updated/deleted docs, total
// chunks rewritten, and task→doc links rebuilt.
type docSyncResult struct {
	Docs    int `json:"docs"`
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Deleted int `json:"deleted"`
	Chunks  int `json:"chunks"`
	Links   int `json:"links"`
}

func docSync(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("doc sync", flag.ContinueOnError)
	// --prune is the default (a deleted file must drop its index rows); the flag
	// exists for symmetry and so callers can be explicit.
	prune := fs.Bool("prune", true, "drop index rows for files no longer on disk")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := syncDocs(db, *prune)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(res)
	}
	fmt.Printf("synced: %d docs (+%d ~%d -%d), %d chunks, %d links\n",
		res.Docs, res.Added, res.Updated, res.Deleted, res.Chunks, res.Links)
	return nil
}

// syncDocs is the core indexer, shared by the CLI and the implicit-sync callers
// (search/get) and the MCP doc_sync tool. It walks README.md + docs/**/*.md,
// blob-hashes each file, short-circuits unchanged hashes, and for changed files
// reparses title/outline and re-chunks the body on H2 boundaries (FTS is
// maintained by the doc_chunks triggers). It then rebuilds task_sources from
// every task body's Sources: line, and (when prune is set) drops rows for
// files that have left disk. Paths are repo-relative with forward slashes.
func syncDocs(db *sql.DB, prune bool) (*docSyncResult, error) {
	files, err := docWalk()
	if err != nil {
		return nil, err
	}

	// Existing index, keyed by path → (id, hash), for hash short-circuiting and
	// prune detection.
	type docRow struct {
		id   int64
		hash string
	}
	known := map[string]docRow{}
	rows, err := db.Query(`SELECT id, path, hash FROM docs`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r docRow
		var path string
		if err := rows.Scan(&r.id, &path, &r.hash); err != nil {
			rows.Close()
			return nil, err
		}
		known[path] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	res := &docSyncResult{}
	now := timeToMs(time.Now())
	seen := map[string]bool{}

	for _, path := range files {
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		hash := gitBlobSHA(data)
		prev, exists := known[path]
		if exists && prev.hash == hash {
			continue // unchanged: skip the reparse/re-chunk entirely
		}

		title, headings := docParseTitleHeadings(string(data))
		var mtime int64 = now
		if fi, err := os.Stat(path); err == nil {
			mtime = timeToMs(fi.ModTime())
		}

		var docID int64
		if exists {
			docID = prev.id
			if _, err := db.Exec(
				`UPDATE docs SET title=?, hash=?, headings=?, mtime=?, indexed_at=? WHERE id=?`,
				title, hash, strings.Join(headings, "\n"), mtime, now, docID,
			); err != nil {
				return nil, err
			}
			res.Updated++
		} else {
			r, err := db.Exec(
				`INSERT INTO docs(path,title,hash,headings,mtime,indexed_at) VALUES(?,?,?,?,?,?)`,
				path, title, hash, strings.Join(headings, "\n"), mtime, now,
			)
			if err != nil {
				return nil, err
			}
			docID, _ = r.LastInsertId()
			res.Added++
		}

		// Re-chunk: drop the doc's old chunks (the docs_ad trigger keeps FTS in
		// step) and reinsert the current H2-boundary slices.
		if _, err := db.Exec(`DELETE FROM doc_chunks WHERE doc_id=?`, docID); err != nil {
			return nil, err
		}
		for _, ch := range docChunkBody(string(data)) {
			if _, err := db.Exec(
				`INSERT INTO doc_chunks(doc_id,path,heading,seq,body,hash) VALUES(?,?,?,?,?,?)`,
				docID, path, ch.heading, ch.seq, ch.body, gitBlobSHA([]byte(ch.body)),
			); err != nil {
				return nil, err
			}
		}
	}

	if prune {
		for path, r := range known {
			if seen[path] {
				continue
			}
			if _, err := db.Exec(`DELETE FROM doc_chunks WHERE doc_id=?`, r.id); err != nil {
				return nil, err
			}
			if _, err := db.Exec(`DELETE FROM docs WHERE id=?`, r.id); err != nil {
				return nil, err
			}
			res.Deleted++
		}
	}

	// Extend the corpus past files: also index task and note bodies as
	// doc_chunks rows under a NEGATIVE surrogate doc_id (surrogateDocID), a
	// space disjoint from real docs.id (positive autoincrement) so a surrogate's
	// DELETE-by-doc_id can never wipe a real doc's chunks. The chunker is the
	// shipped chunkTask/chunkNote (chunk_tasknotes.go), which reproduces the
	// SAME hash a doc chunk of identical text would — the dedup property.
	if err := syncTaskNoteChunks(db, prune); err != nil {
		return nil, err
	}

	// Gate the task_sources rebuild: it is a full wipe+reinsert of ~260 rows, so
	// running it on every implicit sync (search/get/link, audit, MCP) needlessly
	// churns the table. Rebuild only when this sync actually changed a doc row
	// (a new/edited/removed doc can change which citations resolve) OR when a task
	// body changed since the last rebuild (the Sources: lines live in task bodies).
	docsChanged := res.Added+res.Updated+res.Deleted > 0
	links, err := docRebuildSources(db, docsChanged)
	if err != nil {
		return nil, err
	}
	res.Links = links

	var chunks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM doc_chunks`).Scan(&chunks); err != nil {
		return nil, err
	}
	res.Chunks = chunks
	res.Docs = len(files)
	return res, nil
}

// syncTaskNoteChunks (re)indexes every task and note body into doc_chunks under
// its per-source NEGATIVE surrogate doc_id, then — when prune is set — drops
// chunks for sources that have left the DB (a deleted task/note, or an emptied
// note). It is the task/note arm of syncDocs' file arm: collect → upsert per
// source via insertTaskNoteChunks (DELETE-then-INSERT keyed on the surrogate) →
// prune the vanished. The surrogate space is disjoint from real docs.id so a
// surrogate can never collide with — and thus never delete — a real doc's
// chunks.
func syncTaskNoteChunks(db *sql.DB, prune bool) error {
	sources, err := collectTaskNoteChunks(db)
	if err != nil {
		return err
	}
	live := make(map[string]bool, len(sources))
	for _, s := range sources {
		live[s.Path] = true
		// insertTaskNoteChunks DELETEs by doc_id then re-inserts: idempotent
		// re-chunk of exactly this source's surrogate slot.
		if err := insertTaskNoteChunks(db, surrogateDocID(s.Path), s.Chunks); err != nil {
			return err
		}
	}
	if prune {
		if _, err := pruneTaskNoteChunks(db, live); err != nil {
			return err
		}
	}
	return nil
}

// docRebuildSources re-derives the whole task_sources index from every task
// body's Sources: line. The task body is the single source of truth for a link
// (docs/22 §2.2); this table is a pure index, so the cheapest correct rebuild
// is a full replace.
//
// Two correctness/efficiency properties, both required (review F3):
//   - Gated: the rebuild is a wipe + ~260 re-inserts, but most syncs change
//     nothing relevant. It runs only when docsChanged (a doc row moved this sync,
//     so which citations resolve may differ) OR when the task-body fingerprint —
//     count(*) plus max(updated_at), stashed in the meta table — has moved since
//     the last rebuild (the Sources: lines live in task bodies). An unchanged
//     sync returns the existing edge count without touching the table.
//   - Atomic: the wipe and the re-inserts run in ONE transaction, so a concurrent
//     reader sees the old index or the new one, never an empty/partial table
//     mid-rebuild.
//
// Returns the number of edges currently in the index (rebuilt or pre-existing).
func docRebuildSources(db *sql.DB, docsChanged bool) (int, error) {
	fp, err := taskBodyFingerprint(db)
	if err != nil {
		return 0, err
	}
	var prevFP string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key='task_sources_fp'`).Scan(&prevFP); err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if !docsChanged && fp == prevFP {
		// Nothing that feeds task_sources moved since the last rebuild.
		return taskSourcesCount(db)
	}

	rows, err := db.Query(`SELECT id, body FROM tasks`)
	if err != nil {
		return 0, err
	}
	type taskBody struct {
		id, body string
	}
	var all []taskBody
	for rows.Next() {
		var tb taskBody
		if err := rows.Scan(&tb.id, &tb.body); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, tb)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM task_sources`); err != nil {
		return 0, err
	}
	links := 0
	for _, tb := range all {
		for _, s := range parseSources(tb.body) {
			// INSERT OR IGNORE: the body can cite the same (doc, section) twice;
			// the PK collapses duplicates rather than erroring.
			r, err := tx.Exec(
				`INSERT OR IGNORE INTO task_sources(task_id,doc_path,section) VALUES(?,?,?)`,
				tb.id, s.DocPath, s.Section,
			)
			if err != nil {
				return 0, err
			}
			if n, _ := r.RowsAffected(); n > 0 {
				links++
			}
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO meta(key,value) VALUES('task_sources_fp',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		fp,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return links, nil
}

// taskBodyFingerprint is a cheap value that moves whenever a task is added,
// removed, or has its body/title/status edited: count(*) over tasks plus the
// max updated_at. (Any body edit bumps updated_at, so this catches every change
// the Sources: parse cares about without hashing 260 bodies.)
func taskBodyFingerprint(db *sql.DB) (string, error) {
	var count int
	var maxUpdated sql.NullInt64
	if err := db.QueryRow(`SELECT COUNT(*), MAX(updated_at) FROM tasks`).Scan(&count, &maxUpdated); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", count, maxUpdated.Int64), nil
}

// taskSourcesCount returns the current edge count, used to report Links when the
// rebuild is skipped.
func taskSourcesCount(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM task_sources`).Scan(&n)
	return n, err
}

// docWalk lists the indexable Markdown corpus — README.md at the repo root plus
// every docs/**/*.md (sessions included) — as sorted repo-relative paths with
// forward slashes. It runs relative to the primary checkout (repoRoot), so the
// stored paths match what `Sources:` lines and `git diff <blob>` expect.
func docWalk() ([]string, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	var out []string
	if _, err := os.Stat(filepath.Join(root, "README.md")); err == nil {
		out = append(out, "README.md")
	}
	docsDir := filepath.Join(root, "docs")
	err = filepath.WalkDir(docsDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // no docs/ dir is not fatal
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// docChunk is one H2-boundary slice of a doc during sync (seq 0 = preamble).
type docChunk struct {
	heading string
	seq     int
	body    string
}

// docChunkBody splits a doc body into H2-boundary chunks: chunk 0 is the
// preamble before the first '## ' heading, then one chunk per H2 section
// (heading line included). '## ' inside a fenced code block is ignored so a
// shell-comment or markdown sample never forges a chunk boundary.
func docChunkBody(body string) []docChunk {
	lines := strings.Split(body, "\n")
	var chunks []docChunk
	cur := docChunk{seq: 0}
	var buf []string
	inFence := false
	flush := func() {
		cur.body = strings.Join(buf, "\n")
		chunks = append(chunks, cur)
		buf = nil
	}
	for _, line := range lines {
		if docFenceLine(line) {
			inFence = !inFence
		}
		if !inFence && strings.HasPrefix(line, "## ") {
			flush()
			cur = docChunk{heading: strings.TrimSpace(line[3:]), seq: len(chunks)}
		}
		buf = append(buf, line)
	}
	flush()
	return chunks
}

// docFenceLine reports whether a line opens or closes a Markdown code fence
// (``` or ~~~, possibly indented, with an optional info string).
func docFenceLine(line string) bool {
	t := strings.TrimLeft(line, " \t")
	return strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~")
}

// docParseTitleHeadings extracts the document title (first '# ' heading) and
// the H2+ outline (each '## '/'### '… heading, fences skipped) for the docs
// row. Headings are returned verbatim including their '#' prefix so the outline
// shows nesting.
func docParseTitleHeadings(body string) (title string, headings []string) {
	inFence := false
	for _, line := range strings.Split(body, "\n") {
		if docFenceLine(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if title == "" && strings.HasPrefix(line, "# ") {
			title = strings.TrimSpace(line[2:])
			continue
		}
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
			headings = append(headings, strings.TrimSpace(line))
		}
	}
	return title, headings
}

// docSearchHit is one FTS result row across either index, carrying the snippet
// excerpt and (for docs) the linked-task count.
type docSearchHit struct {
	Kind        string `json:"kind"` // "doc" | "task" | "note"
	Path        string `json:"path,omitempty"`
	Heading     string `json:"heading,omitempty"`
	TaskID      string `json:"task_id,omitempty"`
	Title       string `json:"title,omitempty"`
	Snippet     string `json:"snippet"`
	LinkedTasks int    `json:"linked_tasks,omitempty"`
	// Score is the fused hybrid score for hits served by the searchsvc /search
	// client (searchsvc_client.go); zero for FTS5/local hits, which rank by
	// bm25 ordering rather than an absolute score.
	Score float64 `json:"score,omitempty"`
}

func docSearch(db *sql.DB, args []string) error {
	// The query is a leading positional (flag.Parse stops at the first non-flag,
	// so flags must follow it) — peeled like every <id> via peelID.
	query, rest, err := peelID(args, "taskdb doc search <query> [--limit 10] [--scope docs|tasks|all] [--raw] [--json]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("doc search", flag.ContinueOnError)
	limit := fs.Int("limit", 10, "max results")
	scope := fs.String("scope", "docs", "docs|tasks|all")
	raw := fs.Bool("raw", false, "pass the query to FTS5 verbatim (no quoted-phrase wrap)")
	asJSON := fs.Bool("json", false, "output JSON")
	// --semantic switches from FTS5 keyword search to cosine-ranked embeddings
	// search (docs/22 §8 seam). The embedder is an external command that reads
	// text on stdin and prints a JSON float array (local-model-first is the
	// proposed default; an API embedder is a config swap — see embeddings.go).
	semantic := fs.Bool("semantic", false, "rank by embedding cosine similarity instead of FTS5 keywords")
	embedderCmd := fs.String("embedder-cmd", "", "external embedder: reads text on stdin, prints a JSON float array (required with --semantic)")
	// --embedder-url points at a running searchsvc instance. With --semantic it
	// (a) embeds via the resident HTTP model instead of spawning embed.py, and
	// (b) the searchsvc /search client is preferred over the local cosine path,
	// FAILING OPEN to local when the service is unreachable. Mutually exclusive
	// with --embedder-cmd (embedderFromFlag rejects setting both).
	embedderURL := fs.String("embedder-url", "", "running searchsvc base URL (e.g. http://127.0.0.1:8099); mutually exclusive with --embedder-cmd")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	// Any further positionals are extra query words (an unquoted multi-word
	// query); join them onto the peeled first token.
	query = strings.TrimSpace(strings.Join(append([]string{query}, fs.Args()...), " "))
	if query == "" {
		return fmt.Errorf("usage: taskdb doc search <query> [--limit 10] [--scope docs|tasks|all] [--raw] [--semantic [--embedder-cmd CMD | --embedder-url URL]] [--json]")
	}
	if *semantic {
		return docSearchSemantic(db, query, *limit, *embedderCmd, *embedderURL, *asJSON)
	}
	switch *scope {
	case "docs", "tasks", "all":
	default:
		return fmt.Errorf("invalid scope %q; must be one of: docs, tasks, all", *scope)
	}
	hits, err := searchDocs(db, query, *scope, *limit, *raw)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(hits)
	}
	if len(hits) == 0 {
		fmt.Println("no matches")
		return nil
	}
	for _, h := range hits {
		printDocSearchHit(h)
	}
	return nil
}

// printDocSearchHit renders one CLI hit line. A task hit shows its id+title; a
// note hit shows its synthetic note:// path; a doc hit shows path › heading. A
// service hit (Score non-zero) prefixes the fused score so a searchsvc-ranked
// result is visibly distinct from an FTS5 one. The snippet/title (whichever is
// populated) follows on an indented line.
func printDocSearchHit(h *docSearchHit) {
	switch h.Kind {
	case "task":
		fmt.Printf("[task %s] %s\n", h.TaskID, h.Title)
	case "note":
		fmt.Printf("[note] %s\n", h.Path)
	default:
		loc := h.Path
		if h.Heading != "" {
			loc += " › " + h.Heading
		}
		if h.Score != 0 {
			fmt.Printf("[doc %.3f] %s\n", h.Score, loc)
		} else {
			fmt.Printf("[doc] %s\n", loc)
		}
	}
	if h.Snippet != "" {
		fmt.Printf("  %s\n", strings.ReplaceAll(h.Snippet, "\n", " "))
	}
}

// searchDocs runs an implicit incremental sync, then FTS5 search over the doc
// chunks (and/or tasks per scope), ordered by bm25/rank, with snippet()
// excerpts. Raw input is wrapped as a quoted phrase unless raw is set — bare
// FTS5 operators in user text are a syntax-error gotcha. Shared with the MCP
// doc_search tool.
func searchDocs(db *sql.DB, query, scope string, limit int, raw bool) ([]*docSearchHit, error) {
	if _, err := syncDocs(db, true); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}
	match := docFTSQuery(query, raw)
	hits := []*docSearchHit{} // empty, not nil: --json prints [] on no match

	if scope == "docs" || scope == "all" {
		rows, err := db.Query(
			`SELECT c.path, c.heading,
				snippet(docs_fts, 1, '[', ']', '…', 12),
				(SELECT COUNT(*) FROM task_sources s WHERE s.doc_path = c.path)
			FROM docs_fts f JOIN doc_chunks c ON c.id = f.rowid
			WHERE docs_fts MATCH ? ORDER BY bm25(docs_fts) LIMIT ?`,
			match, limit,
		)
		if err != nil {
			return nil, docFTSError(err, raw)
		}
		for rows.Next() {
			h := &docSearchHit{Kind: "doc"}
			if err := rows.Scan(&h.Path, &h.Heading, &h.Snippet, &h.LinkedTasks); err != nil {
				rows.Close()
				return nil, err
			}
			hits = append(hits, h)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	if scope == "tasks" || scope == "all" {
		rows, err := db.Query(
			`SELECT t.id, t.title, snippet(tasks_fts, 1, '[', ']', '…', 12)
			FROM tasks_fts f JOIN tasks t ON t.rowid = f.rowid
			WHERE tasks_fts MATCH ? ORDER BY bm25(tasks_fts) LIMIT ?`,
			match, limit,
		)
		if err != nil {
			return nil, docFTSError(err, raw)
		}
		for rows.Next() {
			h := &docSearchHit{Kind: "task"}
			if err := rows.Scan(&h.TaskID, &h.Title, &h.Snippet); err != nil {
				rows.Close()
				return nil, err
			}
			hits = append(hits, h)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return hits, nil
}

// docFTSQuery prepares user input for an FTS5 MATCH: by default the whole query
// is wrapped as one double-quoted phrase (embedded quotes doubled) so operator
// characters can't trigger a syntax error; --raw passes it through verbatim for
// callers who want the FTS5 mini-language.
func docFTSQuery(query string, raw bool) string {
	if raw {
		return query
	}
	return `"` + strings.ReplaceAll(query, `"`, `""`) + `"`
}

// docFTSError names the FTS5 mini-language when a --raw query fails to parse,
// so the caller knows the syntax is theirs to fix.
func docFTSError(err error, raw bool) error {
	if raw {
		return fmt.Errorf("FTS5 query syntax error (--raw uses the FTS5 mini-language): %w", err)
	}
	return err
}

// docResult is the get payload: the docs row plus the on-disk body and the
// chunk outline (and selected section chunks when --section is given).
type docResult struct {
	*Doc
	Body     string      `json:"body,omitempty"`
	Outline  []string    `json:"outline,omitempty"`
	Sections []*DocChunk `json:"sections,omitempty"`
}

func docGet(db *sql.DB, args []string) error {
	ref, rest, err := peelID(args, "taskdb doc get <path-or-suffix> [--section S] [--outline] [--json]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("doc get", flag.ContinueOnError)
	section := fs.String("section", "", "return chunks whose heading has this prefix")
	outline := fs.Bool("outline", false, "print the heading outline only")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	doc, body, chunks, err := getDoc(db, ref, *section)
	if err != nil {
		return err
	}

	if *asJSON {
		out := &docResult{Doc: doc, Outline: docOutline(doc)}
		if *section != "" {
			out.Sections = chunks
		} else if !*outline {
			out.Body = body
		}
		return printJSON(out)
	}
	if *outline {
		fmt.Printf("%s — %s\n", doc.Path, doc.Title)
		for _, h := range docOutline(doc) {
			fmt.Println("  " + h)
		}
		return nil
	}
	if *section != "" {
		if len(chunks) == 0 {
			fmt.Printf("no section in %s matching %q\n", doc.Path, *section)
			return nil
		}
		for _, c := range chunks {
			fmt.Println(c.Body)
		}
		return nil
	}
	fmt.Println(body)
	return nil
}

// getDoc resolves a doc by exact repo-relative path else by a unique path
// suffix (mirroring resolveTaskID's wording), reads the whole body from DISK
// (the file is the truth), and — when section is non-empty — returns the
// chunks whose heading carries that prefix. Implicit-syncs first so a freshly
// edited doc resolves and serves current text. Shared with the MCP doc_get
// tool.
func getDoc(db *sql.DB, ref, section string) (*Doc, string, []*DocChunk, error) {
	if _, err := syncDocs(db, true); err != nil {
		return nil, "", nil, err
	}
	doc, err := docResolve(db, ref)
	if err != nil {
		return nil, "", nil, err
	}
	root, err := repoRoot()
	if err != nil {
		return nil, "", nil, err
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(doc.Path)))
	if err != nil {
		return nil, "", nil, err
	}

	var chunks []*DocChunk
	if section != "" {
		rows, err := db.Query(
			`SELECT id, doc_id, path, heading, seq, body, hash FROM doc_chunks
			WHERE doc_id=? AND heading LIKE ? ORDER BY seq`,
			doc.ID, section+"%",
		)
		if err != nil {
			return nil, "", nil, err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanChunk(rows)
			if err != nil {
				return nil, "", nil, err
			}
			chunks = append(chunks, c)
		}
		if err := rows.Err(); err != nil {
			return nil, "", nil, err
		}
	}
	return doc, string(data), chunks, nil
}

// docResolve maps a doc reference to its row: an exact path match first, else a
// unique path suffix. Ambiguity and absence reuse resolveTaskID's error
// wording so the two resolvers feel the same.
func docResolve(db *sql.DB, ref string) (*Doc, error) {
	ref = filepath.ToSlash(strings.TrimSpace(ref))
	if ref == "" {
		return nil, fmt.Errorf("empty doc path")
	}
	rows, err := db.Query(`SELECT id, path, title, hash, headings, mtime, indexed_at FROM docs WHERE path=?`, ref)
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		d, err := scanDoc(rows)
		rows.Close()
		return d, err
	}
	rows.Close()

	// Suffix match: "21-taskdb-design.md" or "taskdb-design.md" → the full path.
	rows, err = db.Query(`SELECT id, path, title, hash, headings, mtime, indexed_at FROM docs WHERE path LIKE ? ORDER BY path`, "%"+ref)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []*Doc
	for rows.Next() {
		d, err := scanDoc(rows)
		if err != nil {
			return nil, err
		}
		matches = append(matches, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("doc %s not found", ref)
	case 1:
		return matches[0], nil
	default:
		paths := make([]string, len(matches))
		for i, m := range matches {
			paths[i] = m.Path
		}
		return nil, fmt.Errorf("ambiguous doc %q matches %d docs: %s", ref, len(matches), strings.Join(paths, ", "))
	}
}

// docOutline splits the stored newline-joined headings back into a slice.
func docOutline(d *Doc) []string {
	if d.Headings == "" {
		return nil
	}
	return strings.Split(d.Headings, "\n")
}

// docLink appends a citation to a task body's trailing Sources: line (creating
// the line if absent), bumps updated_at, and re-derives that one task's
// task_sources rows. The frozen JSON body stays the single source of truth;
// the table is a pure index (docs/22 §3). The doc path is resolved against the
// live index, so a typo fails loudly instead of citing a nonexistent file.
func docLink(db *sql.DB, args []string) error {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return fmt.Errorf("usage: taskdb doc link <task-id> <doc-path> [--section S]")
	}
	idRef, docRef, rest := args[0], args[1], args[2:]
	fs := flag.NewFlagSet("doc link", flag.ContinueOnError)
	section := fs.String("section", "", "section fragment to cite (e.g. \"§4\")")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	id, err := resolveTaskID(db, idRef)
	if err != nil {
		return err
	}
	if _, err := syncDocs(db, true); err != nil {
		return err
	}
	doc, err := docResolve(db, docRef)
	if err != nil {
		return err
	}

	t, err := getTask(db, id)
	if err != nil {
		return err
	}
	citation := doc.Path
	if *section != "" {
		citation += " " + strings.TrimSpace(*section)
	}
	t.Body = docAppendCitation(t.Body, citation)

	if _, err := db.Exec(`UPDATE tasks SET body=?, updated_at=? WHERE id=?`, t.Body, timeToMs(time.Now()), id); err != nil {
		return err
	}
	if err := docRederiveTask(db, id, t.Body); err != nil {
		return err
	}
	fmt.Printf("linked task %s → %s\n", id, citation)
	return nil
}

// docAppendCitation adds a citation to a body's trailing Sources: line. If a
// Sources: line exists it appends "; <citation>" to the LAST one (the parser's
// canonical line); otherwise it appends a fresh "Sources: <citation>" line,
// separated from the body by a blank line. An already-present identical
// citation is left untouched.
func docAppendCitation(body, citation string) string {
	loc := docSourcesLineRe.FindAllStringSubmatchIndex(body, -1)
	if len(loc) == 0 {
		sep := "\n\n"
		if body == "" {
			sep = ""
		} else if strings.HasSuffix(body, "\n") {
			sep = "\n"
		}
		return body + sep + "Sources: " + citation
	}
	last := loc[len(loc)-1]
	lineStart, lineEnd := last[0], last[1]
	line := body[lineStart:lineEnd]
	for _, frag := range strings.Split(strings.TrimPrefix(line, "Sources:"), ";") {
		if strings.TrimSpace(frag) == citation {
			return body // already cited
		}
	}
	return body[:lineEnd] + "; " + citation + body[lineEnd:]
}

// docRederiveTask rebuilds just one task's task_sources rows from its body —
// the targeted counterpart to docRebuildSources, used after a single-task body
// edit so we don't rescan all 240+ bodies.
func docRederiveTask(db *sql.DB, id, body string) error {
	if _, err := db.Exec(`DELETE FROM task_sources WHERE task_id=?`, id); err != nil {
		return err
	}
	for _, s := range parseSources(body) {
		if _, err := db.Exec(
			`INSERT OR IGNORE INTO task_sources(task_id,doc_path,section) VALUES(?,?,?)`,
			id, s.DocPath, s.Section,
		); err != nil {
			return err
		}
	}
	return nil
}

// docEmbed is the incremental-indexing CLI verb for the embeddings seam
// (docs/22 §8). It implicit-syncs the corpus first (so freshly edited docs are
// chunked), then embeds ONLY chunk hashes not already in the cache — unchanged
// chunks are never re-embedded. The embedder is an external command; the
// no-embedder case fails loudly rather than silently indexing nothing.
func docEmbed(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("doc embed", flag.ContinueOnError)
	embedderCmd := fs.String("embedder-cmd", "", "external embedder: reads text on stdin, prints a JSON float array")
	// --embedder-url targets a running searchsvc instance (resident model) instead
	// of spawning embed.py per chunk; mutually exclusive with --embedder-cmd.
	embedderURL := fs.String("embedder-url", "", "running searchsvc base URL (e.g. http://127.0.0.1:8099); mutually exclusive with --embedder-cmd")
	// --service-url is ADDITIVE to --embedder-url and orthogonal to it: after the
	// local embed pass writes the cache, the changed doc_chunks set is PUSHED to a
	// running searchsvc instance so its resident index (re)absorbs them and
	// /reindex prunes the vanished. Fail-open: unset is a no-op, an unreachable
	// service emits a loud degraded banner and is NEVER a hard failure (the local
	// cache write is authoritative). Distinct from --embedder-url, which selects
	// WHICH embedder the local pass uses; --service-url selects WHERE to push the
	// result. Either, both, or neither may be set.
	serviceURL := fs.String("service-url", "", "running searchsvc base URL to PUSH the changed chunk set to after embedding (fail-open; additive to --embedder-url)")
	// --backfill-provenance is ADDITIVE and defaults OFF. When set AND --service-url
	// is configured, after the changed-set push the embed run asks the service to
	// HEAL resident chunks that landed with EMPTY provenance (doc_path/heading) —
	// the chunks streamed before the provenance-pushers fix — via its targeted
	// /backfill_provenance route, instead of waiting for a full /reindex. It calls
	// the EXISTING triggerBackfillProvenance (searchsvc_ingest.go), which is
	// FAIL-OPEN identical to the push: an unset/unreachable service is a loud,
	// non-fatal degraded no-op, NEVER a hard failure. With --service-url unset the
	// flag is a silent no-op (nothing to call).
	backfill := fs.Bool("backfill-provenance", false, "after the push, ask --service-url to heal resident chunks with empty provenance via /backfill_provenance (fail-open; requires --service-url)")
	prune := fs.Bool("prune", true, "drop cache rows for chunk hashes no longer on disk")
	// Default ON: a cache row produced by a different embedder than the active one
	// is re-embedded under the active model so the index can never silently mix
	// models. This is an explicit OFF switch (opt-out), never an opt-in — passing
	// --reembed-on-model-change=false leaves stale vectors in place this pass.
	reembed := fs.Bool("reembed-on-model-change", true, "re-embed cache rows whose model/dims differ from the active embedder (off leaves them stale)")
	// --max-batch is the OPT-IN max-batch WINDOW: when a batch-capable embedder
	// (--embedder-cmd's --batch wire shape, or --embedder-url) is used, cap how many
	// chunk texts ride a single EmbedBatch invocation. 0 (default) = UNLIMITED — the
	// whole to-embed set in one invocation, the pre-windowing behavior verbatim. A
	// positive N splits the set into order-preserving windows of at most N (one
	// invocation each, results concatenated in order); reach for it when an embedder
	// rejects an over-large request body (an API per-request item/token ceiling) or
	// to bound memory on a cold full-corpus index. It never changes result order or
	// content — only how many round-trips the pass makes — and a non-batch embedder
	// ignores it entirely (the per-chunk path is unaffected).
	maxBatch := fs.Int("max-batch", 0, "max chunk texts per batch-embed invocation (0 = unlimited; only affects a batch-capable embedder)")
	// --batch-embedder is the OPT-IN that turns batching ON for the index pass. By
	// default an --embedder-cmd is driven one-text-per-process (the legacy contract);
	// with this flag the configured command is wrapped so the index pass sends many
	// chunk texts in a single `--batch` invocation, amortizing the per-chunk spawn
	// cost. It is a no-op for an --embedder-url embedder (already batch-capable) and,
	// when absent, the per-chunk contract is untouched. A misbehaving batch child
	// degrades LOUDLY to the per-chunk path (per window), so the opt-in is safe.
	batchEmbedder := fs.Bool("batch-embedder", false, "drive the configured --embedder-cmd in batch mode for the index pass (sends many chunks per invocation; default one-text-per-process)")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Record the opt-in window size before embedding; embedTexts reads it via
	// embedBatchWindow. A negative value is clamped to 0 (unlimited) by the setter.
	setMaxEmbedBatch(*maxBatch)
	emb, err := embedderFromFlag(*embedderCmd, *embedderURL)
	if err != nil {
		return err
	}
	// OPT-IN batch mode for the index pass: wrap the configured embedder so a plain
	// --embedder-cmd drives its --batch wire shape. A no-op for an already
	// batch-capable embedder (--embedder-url). The default (flag unset) leaves the
	// one-text-per-invocation contract verbatim.
	if *batchEmbedder {
		emb = maybeWithBatch(emb)
	}
	// Sync first so the chunk set is current before we diff hashes against the
	// cache (a stale chunk table would skip newly added text).
	if _, err := syncDocs(db, true); err != nil {
		return err
	}
	res, err := embedChunksOpts(embedContext(), db, emb, *prune, *reembed)
	if err != nil {
		return err
	}
	// Additive push (+ optional provenance backfill): when --service-url is set,
	// push the changed chunk set to the running searchsvc and trigger its /reindex
	// so the resident index tracks the cache we just wrote, then — when
	// --backfill-provenance is set — heal any resident chunks that landed with empty
	// provenance. FAIL-OPEN — an unset URL is a silent no-op and an unreachable
	// service degrades loudly (the banner) but never fails the embed run. A genuine
	// DB error still surfaces.
	if err := pushAndBackfill(embedContext(), db, *serviceURL, *backfill, *asJSON); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(res)
	}
	// Surface model-swap-driven re-embeds distinctly so an operator who just
	// changed --embedder-cmd (or toggled the local model) sees the index heal.
	swap := ""
	if res.Reembedded > 0 {
		swap = fmt.Sprintf(" [%d model-swap re-embeds]", res.Reembedded)
	}
	fmt.Printf("embedded: +%d ~skip %d -prune %d (of %d chunk hashes)%s\n",
		res.Embedded, res.Skipped, res.Pruned, res.Total, swap)
	return nil
}

// pushAndBackfill is the post-embed maintenance step `doc embed` runs once the
// local cache is written: it PUSHES the changed chunk set to a running searchsvc
// (when serviceURL is set) and — when backfill is true — asks that same service
// to HEAL resident chunks carrying empty provenance via the EXISTING
// triggerBackfillProvenance (searchsvc_ingest.go). Factored out of docEmbed so the
// service-URL wiring (push, then conditional backfill) is directly unit-testable
// against an httptest server without dragging in syncDocs/the embedder.
//
// FAIL-OPEN is the load-bearing property, inherited verbatim from
// pushChangedChunks/triggerBackfillProvenance:
//   - An empty serviceURL is a SILENT no-op for BOTH steps — there is nothing to
//     push to and nothing to heal; the embed run already wrote the authoritative
//     local cache. The backfill flag with no service is therefore inert.
//   - A reachable-but-failing service degrades LOUDLY (the helpers emit the
//     "[searchsvc DEGRADED]" banner) and returns a degraded result, NEVER a hard
//     error — so an embed run against a down service still succeeds.
//
// Only a genuine, non-fail-open error (a DB error surfaced by the push, which
// would also abort docEmbed before) propagates back to the caller.
func pushAndBackfill(ctx context.Context, db *sql.DB, serviceURL string, backfill, asJSON bool) error {
	if strings.TrimSpace(serviceURL) == "" {
		// Nothing configured: both the push and the backfill are silent no-ops.
		return nil
	}
	push, perr := pushChangedChunks(ctx, db, serviceURL, false)
	if perr != nil {
		return perr
	}
	if !asJSON && !push.Degraded {
		fmt.Printf("pushed: +%d chunks -prune %d → searchsvc (reindex=%t)\n",
			push.Pushed, push.Pruned, push.Reindex)
	}
	if !backfill {
		return nil
	}
	// Heal resident chunks with empty provenance. triggerBackfillProvenance is
	// fail-open: an unreachable service bannered, a degraded result, never an error.
	bf, berr := triggerBackfillProvenance(ctx, serviceURL)
	if berr != nil {
		// Defensive: triggerBackfillProvenance fails open and does not return an
		// error today, but honor the signature — surface anything it ever does.
		return berr
	}
	if !asJSON && !bf.Degraded {
		fmt.Printf("backfilled provenance: %d resident chunks healed → searchsvc\n", bf.Healed)
	}
	return nil
}

// staleBanner renders the one-line operator warning for a freshness verdict, or
// "" when the index is fresh (nothing to warn about). A nil result (the check
// could not run) is treated as a warnable unknown so a missing signal is never
// silently read as fresh. When the freshnessResult carries a positive drift
// COUNT (chunks added/edited/removed since the last push), the banner QUANTIFIES
// the staleness ("N chunks changed") so the operator sees the magnitude, not
// just the yes/no verdict; a zero/unknown drift (nil result, or a stale verdict
// whose count is 0) keeps the plain verdict+remedy wording. Kept pure (no IO) so
// it is directly unit-testable.
func staleBanner(f *freshnessResult) string {
	if f != nil && f.Fresh {
		return ""
	}
	if f != nil && f.Drift > 0 {
		unit := "chunks"
		if f.Drift == 1 {
			unit = "chunk"
		}
		return fmt.Sprintf(
			"[searchsvc STALE] resident index is STALE — %d %s changed since the last push — run /reindex (or `taskdb doc embed --service-url <url>`) to refresh",
			f.Drift, unit)
	}
	return "[searchsvc STALE] resident index is STALE (corpus drifted since the last push) — run /reindex (or `taskdb doc embed --service-url <url>`) to refresh"
}

// emitFreshnessBanner runs the Go-side freshness check against db and, when the
// resident index is not fresh, writes the stale banner to searchWarnOut (the same
// sink the degraded banner uses, so a test can capture it). Best-effort: a check
// error still warns (an unknown verdict is not "fresh"), and the search that
// already returned is never failed by it.
func emitFreshnessBanner(db *sql.DB) {
	f, err := freshnessCheck(db)
	if err != nil {
		// The verdict could not be computed — warn rather than silently imply fresh.
		f = nil
	}
	if banner := staleBanner(f); banner != "" {
		fmt.Fprintln(searchWarnOut, banner)
	}
}

// docSearchSemantic runs the embeddings path of `doc search`. With
// --embedder-url it PREFERS the running searchsvc /search endpoint (full hybrid
// dense+sparse fusion served by the resident model), FAILING OPEN to the local
// pure-Go cosine path when the service is unset OR unreachable/erroring — a dead
// service degrades the search loudly (a stderr banner) but never hard-fails. The
// local path syncs, incrementally embeds new chunks, then ranks by query/chunk
// cosine similarity. Relevant-first ordering is the acceptance property either
// way. Shares the external-embedder seam with doc embed.
func docSearchSemantic(db *sql.DB, query string, limit int, embedderCmd, embedderURL string, asJSON bool) error {
	// Service path first: when a searchsvc URL is configured and reachable, its
	// hybrid /search is authoritative. A failure here is non-fatal — we fall
	// through to the local path below.
	if strings.TrimSpace(embedderURL) != "" {
		hits, ok := trySearchService(embedContext(), embedderURL, query, limit)
		if ok {
			// The service served the hybrid ranking; surface the freshness
			// verdict so a stale resident index (corpus drifted since the last
			// push/reindex) is visible BEFORE the results, not silently trusted.
			// freshnessCheck is the Go-side digest compare; a stale verdict prints
			// a one-line banner to stderr. Best-effort: a check error is itself a
			// reason to warn, never to fail the search that already succeeded.
			emitFreshnessBanner(db)
			return renderSemanticHits(hitsToSemantic(hits), asJSON, hits)
		}
		// ok == false: the client already emitted a loud degraded banner; fall
		// through to the local cosine path so the search still returns results.
	}

	emb, err := embedderFromFlag(embedderCmd, embedderURL)
	if err != nil {
		return err
	}
	if _, err := syncDocs(db, true); err != nil {
		return err
	}
	// Embed any chunks added/changed since the last pass so the search sees the
	// current corpus; cached chunks are skipped (never re-embedded).
	if _, err := embedChunks(embedContext(), db, emb, true); err != nil {
		return err
	}
	hits, err := semanticSearch(embedContext(), db, emb, query, limit, true)
	if err != nil {
		return err
	}
	return renderSemanticHits(hits, asJSON, nil)
}

// renderSemanticHits prints semantic hits as JSON or as the human "[doc SCORE]"
// listing. When svcHits is non-nil it is the searchsvc /search result set and
// is what JSON emits (preserving the fused/dense/sparse score breakdown); the
// human listing always renders the passed semanticHit slice. A doc:// path that
// is actually a task:///note:// synthetic URI prints with its kind label.
func renderSemanticHits(hits []*semanticHit, asJSON bool, svcHits []*docSearchHit) error {
	if asJSON {
		if svcHits != nil {
			return printJSON(svcHits)
		}
		return printJSON(hits)
	}
	if len(hits) == 0 {
		fmt.Println("no matches")
		return nil
	}
	for _, h := range hits {
		loc := h.Path
		if h.Heading != "" {
			loc += " › " + h.Heading
		}
		fmt.Printf("[%s %.3f] %s\n", semanticPathKind(h.Path), h.Score, loc)
		excerpt := strings.ReplaceAll(strings.TrimSpace(h.Body), "\n", " ")
		if len(excerpt) > 160 {
			excerpt = excerpt[:160] + "…"
		}
		if excerpt != "" {
			fmt.Printf("  %s\n", excerpt)
		}
	}
	return nil
}

// semanticPathKind labels a chunk path by its scheme: a task:///note:// synthetic
// URI prints as "task"/"note", a real file path as "doc".
func semanticPathKind(path string) string {
	switch {
	case strings.HasPrefix(path, taskChunkScheme):
		return "task"
	case strings.HasPrefix(path, noteChunkScheme):
		return "note"
	default:
		return "doc"
	}
}

// hitsToSemantic adapts searchsvc /search hits to the semanticHit shape the
// human renderer consumes (Path/Heading/Score). The searchsvc result carries no
// body, so the excerpt line is empty for service hits.
func hitsToSemantic(hits []*docSearchHit) []*semanticHit {
	out := make([]*semanticHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, &semanticHit{
			Path:    h.Path,
			Heading: h.Heading,
			Score:   h.Score,
		})
	}
	return out
}

// embedderFromFlag selects the embedder from the two mutually-exclusive CLI
// flags. --embedder-url targets a running searchsvc instance over HTTP
// (newHTTPEmbedder, which reports the stable "bge-m3-http" model label so
// activeSignature's model-swap healing already works); --embedder-cmd spawns an
// external process-per-chunk embedder (newCmdEmbedder). Setting BOTH is a loud
// error — there is exactly one active embedder. An empty cmd is the legacy
// loud-failure case newCmdEmbedder already enforces.
//
// The --embedder-cmd string is split on whitespace into argv (no shell —
// quoting-free simple commands like "python3 scripts/taskdb/embedder/embed.py");
// a caller needing shell features wraps them in a script.
func embedderFromFlag(embedderCmd, embedderURL string) (Embedder, error) {
	cmd := strings.TrimSpace(embedderCmd)
	url := strings.TrimSpace(embedderURL)
	if cmd != "" && url != "" {
		return nil, fmt.Errorf("--embedder-cmd and --embedder-url are mutually exclusive; pass exactly one")
	}
	if url != "" {
		return newHTTPEmbedder(url)
	}
	return newCmdEmbedder(strings.Fields(embedderCmd))
}
