// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The audit family emits deterministic staleness signals over the live DB — no
// LLM, no git exec (docs/22 §3). Each verb returns a typed findings struct; the
// CLI prints it (terse lines by default, --json for the curation workflows).
// `audit all` concatenates the three and groups findings by workstream root.
//
// CONTRACT: the --json field names below are the input contract for
// .claude/workflows/ (docs/22 §7). They are stable on purpose — the curation
// runners read these exact keys. Keep them in sync with the JSON tags on the
// audit* structs in this file; do not rename a field without updating every
// workflow that consumes it.
//
// auditReport is the top-level `audit all --json` shape:
//
//	{
//	  "drift":  {docs:[{path,current_hash,audited_hash?,audited_at?,linked_tasks,state}],
//	             dangling_links:[{task_id,doc_path,section}],
//	             broken_anchors:[{task_id,doc_path,section,heading_count}]},
//	  "stuck":  {stale_locks:[...], idle_in_progress:[...],
//	             done_worktrees:[...], missing_worktrees:[...]},
//	  "dag":    {cycles:[[id,...]], missing_deps:[{task_id,depends_on}],
//	             stale_epics:[{id,title}], unsourced:[{id,title}],
//	             bad_sources:[{task_id,doc_path}], poison:[{id,title,failures}],
//	             roots:[{root,title,ready,starved}]},
//	  "workstreams": [{root,title,findings:N}]   // grouping index, audit all only
//	}
//
// Every leaf carries the task/doc identity a curator needs to act through the
// CLI; nothing here mutates state.

func cmdAudit(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb audit <drift|stuck|dag|all|watermarks|work>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "drift":
		return auditDriftCmd(db, rest)
	case "stuck":
		return auditStuckCmd(db, rest)
	case "dag":
		return auditDagCmd(db, rest)
	case "all":
		return auditAllCmd(db, rest)
	case "watermarks":
		return auditWatermarksCmd(db, rest)
	case "work":
		// `audit work` is an alias for the top-level `work` triage view — it lives
		// in cmd_work.go and shares the same read-only flag surface.
		return cmdWork(db, rest)
	default:
		return fmt.Errorf("unknown audit subcommand: %s", sub)
	}
}

// --- drift ---------------------------------------------------------------

// auditDocState is one doc's reconciliation status: its current blob-hash short
// prefix, the last watermark note's hash/time (when one exists), how many tasks
// cite it, and a derived state.
type auditDocState struct {
	Path        string `json:"path"`
	CurrentHash string `json:"current_hash"`           // substr(docs.hash,1,7)
	AuditedHash string `json:"audited_hash,omitempty"` // newest doc-audit: watermark
	AuditedAt   string `json:"audited_at,omitempty"`   // RFC3339 of that note
	LinkedTasks int    `json:"linked_tasks"`
	State       string `json:"state"` // ok | drifted | never-audited
}

// auditDanglingLink is a task_sources edge whose cited doc is no longer indexed
// (the file left disk) — a citation a curator must repoint or drop.
type auditDanglingLink struct {
	TaskID  string `json:"task_id"`
	DocPath string `json:"doc_path"`
	Section string `json:"section,omitempty"`
}

// auditBrokenAnchor is a "§N" section fragment whose number exceeds the cited
// doc's parseable numbered-H2 count — a best-effort stale-anchor signal.
type auditBrokenAnchor struct {
	TaskID       string `json:"task_id"`
	DocPath      string `json:"doc_path"`
	Section      string `json:"section"`
	HeadingCount int    `json:"heading_count"`
}

// auditDrift is the `audit drift` findings: per-doc reconciliation state plus
// the two citation-integrity lists.
type auditDrift struct {
	Docs          []auditDocState     `json:"docs"`
	DanglingLinks []auditDanglingLink `json:"dangling_links"`
	BrokenAnchors []auditBrokenAnchor `json:"broken_anchors"`
}

// auditWatermarkNoteRe parses a doc-audit watermark note (docs/22 §2.3): the
// doc path and the 7-hex blob prefix that doc was last reconciled at. The newest
// such note per path is the drift baseline.
var auditWatermarkNoteRe = regexp.MustCompile(`^doc-audit:\s+(\S+)\s+@\s+([0-9a-f]{7})\s+ok\b`)

// auditAnchorRe pulls a numeric section index off a "§N" fragment (also "§N.M"
// and bare "N"-leading forms like "section 7"), so a citation to a section past
// the doc's last numbered H2 can be flagged. Group 1 is the leading integer.
var auditAnchorRe = regexp.MustCompile(`§\s*([0-9]+)`)

func auditDriftCmd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("audit drift", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := auditDriftFindings(db)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(d)
	}
	for _, doc := range d.Docs {
		switch doc.State {
		case "ok":
			continue // unchanged since the last watermark — nothing to report
		case "drifted":
			fmt.Printf("drifted: %s (%s, audited %s)\n", doc.Path, doc.CurrentHash, doc.AuditedHash)
		case "never-audited":
			fmt.Printf("never-audited: %s (%s)\n", doc.Path, doc.CurrentHash)
		}
	}
	for _, l := range d.DanglingLinks {
		fmt.Printf("dangling: task %s cites missing %s\n", l.TaskID, l.DocPath)
	}
	for _, a := range d.BrokenAnchors {
		fmt.Printf("broken-anchor: task %s cites %s %s (doc has %d numbered sections)\n", a.TaskID, a.DocPath, a.Section, a.HeadingCount)
	}
	return nil
}

// auditDriftFindings runs an implicit doc sync (so hashes and links are
// current), then computes per-doc reconciliation state, dangling citations, and
// best-effort broken section anchors. Shared by `audit drift` and `audit all`.
func auditDriftFindings(db *sql.DB) (*auditDrift, error) {
	if _, err := syncDocs(db, true); err != nil {
		return nil, err
	}
	out := &auditDrift{
		Docs:          []auditDocState{},
		DanglingLinks: []auditDanglingLink{},
		BrokenAnchors: []auditBrokenAnchor{},
	}

	// Newest watermark per doc path, from taskless notes (the baseline survives
	// drop-and-thaw because notes freeze, docs/22 §2.3).
	baseline, err := auditWatermarks(db)
	if err != nil {
		return nil, err
	}

	// Linked-task counts per doc path, one query rather than a per-doc COUNT.
	linkCount := map[string]int{}
	lrows, err := db.Query(`SELECT doc_path, COUNT(*) FROM task_sources GROUP BY doc_path`)
	if err != nil {
		return nil, err
	}
	for lrows.Next() {
		var p string
		var c int
		if err := lrows.Scan(&p, &c); err != nil {
			lrows.Close()
			return nil, err
		}
		linkCount[p] = c
	}
	lrows.Close()
	if err := lrows.Err(); err != nil {
		return nil, err
	}

	// Numbered-H2 count per doc (for the anchor check) keyed by path, built from
	// the stored outline as we walk the docs.
	headingCount := map[string]int{}

	rows, err := db.Query(`SELECT path, hash, headings FROM docs ORDER BY path`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var path, hash, headings string
		if err := rows.Scan(&path, &hash, &headings); err != nil {
			rows.Close()
			return nil, err
		}
		headingCount[path] = auditNumberedH2(headings)
		cur := auditShortHash(hash)
		ds := auditDocState{Path: path, CurrentHash: cur, LinkedTasks: linkCount[path]}
		if wm, ok := baseline[path]; ok {
			ds.AuditedHash = wm.hash
			ds.AuditedAt = wm.at.Format(time.RFC3339)
			if wm.hash == cur {
				ds.State = "ok"
			} else {
				ds.State = "drifted"
			}
		} else {
			ds.State = "never-audited"
		}
		out.Docs = append(out.Docs, ds)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Citation integrity: dangling links (doc gone) and broken anchors (§N past
	// the doc's numbered-H2 count). One pass over task_sources.
	srows, err := db.Query(
		`SELECT s.task_id, s.doc_path, s.section, d.path IS NULL
		FROM task_sources s LEFT JOIN docs d ON d.path = s.doc_path
		ORDER BY s.task_id, s.doc_path, s.section`,
	)
	if err != nil {
		return nil, err
	}
	for srows.Next() {
		var taskID, docPath, section string
		var missing bool
		if err := srows.Scan(&taskID, &docPath, &section, &missing); err != nil {
			srows.Close()
			return nil, err
		}
		if missing {
			out.DanglingLinks = append(out.DanglingLinks, auditDanglingLink{TaskID: taskID, DocPath: docPath, Section: section})
			continue
		}
		if n, ok := auditAnchorIndex(section); ok {
			if hc := headingCount[docPath]; hc > 0 && n > hc {
				out.BrokenAnchors = append(out.BrokenAnchors, auditBrokenAnchor{
					TaskID: taskID, DocPath: docPath, Section: section, HeadingCount: hc,
				})
			}
		}
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// auditWatermark is a parsed doc-audit note: the reconciled hash prefix and the
// note's creation time, used to pick the newest baseline per doc.
type auditWatermark struct {
	hash string
	at   time.Time
}

// auditWatermarks returns the newest doc-audit watermark per doc path, parsed
// from taskless notes. Notes are walked newest-first so the first match per
// path wins.
func auditWatermarks(db *sql.DB) (map[string]auditWatermark, error) {
	rows, err := db.Query(
		`SELECT body, created_at FROM notes WHERE task_id IS NULL ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]auditWatermark{}
	for rows.Next() {
		var body string
		var createdMs int64
		if err := rows.Scan(&body, &createdMs); err != nil {
			return nil, err
		}
		m := auditWatermarkNoteRe.FindStringSubmatch(strings.TrimSpace(body))
		if m == nil {
			continue
		}
		path := m[1]
		if _, seen := out[path]; seen {
			continue // an older note for the same doc; the newest already won
		}
		out[path] = auditWatermark{hash: m[2], at: msToTime(createdMs)}
	}
	return out, rows.Err()
}

// --- watermarks (read-only OQ5 reopen-trigger gauge) ----------------------

// auditWatermarksReadout is the `audit watermarks` findings: a read-only count of
// doc-audit watermark notes (docs/22 §2.3) and how many are superseded — the
// gauge for the docs/22 §10 OQ5 ~50-superseded reopen trigger. It mutates
// nothing; the deferred `note prune` sweep is NOT shipped here (OQ5 stays gated).
//
// matched    = taskless notes whose body parses as a doc-audit watermark
// baselines  = distinct doc paths with a watermark (the newest-per-path baseline
// that `audit drift` reads via auditWatermarks)
// superseded = matched − baselines (the older, non-newest watermarks)
// trigger    = the OQ5 reopen threshold; tripped is superseded >= trigger
type auditWatermarksReadout struct {
	Matched    int  `json:"matched"`
	Baselines  int  `json:"baselines"`
	Superseded int  `json:"superseded"`
	Trigger    int  `json:"trigger"`
	Tripped    bool `json:"tripped"`
}

// auditOQ5SupersededTrigger is the docs/22 §10 OQ5 reopen threshold: once
// superseded doc-audit watermarks reach ~50, the deferred `note prune` sentinel
// becomes worth proposing. Kept here as one named literal so the readout and the
// docs cite the same number.
const auditOQ5SupersededTrigger = 50

// auditWatermarksFindings counts doc-audit watermark notes and derives the
// superseded total, reusing auditWatermarks() for the newest-per-path baseline so
// "baseline" means exactly what `audit drift` reconciles against. The matched
// total comes from one COUNT over the same taskless-note shape; superseded is the
// difference. Read-only: no note is dropped — that is the deferred OQ5 `note
// prune` sweep, which this gauge only measures the trigger for.
func auditWatermarksFindings(db *sql.DB) (*auditWatermarksReadout, error) {
	baseline, err := auditWatermarks(db)
	if err != nil {
		return nil, err
	}

	// Total matching watermark notes. The GLOB mirrors auditWatermarkNoteRe's
	// shape (`doc-audit: <path> @ <hash7> ok …`, taskless notes only) at the SQL
	// layer; a Go-side re-parse below keeps the count exactly aligned with the
	// regex auditWatermarks() uses, so matched − baselines can never disagree with
	// the parser even if the GLOB is looser.
	rows, err := db.Query(
		`SELECT body FROM notes WHERE task_id IS NULL
		AND body GLOB 'doc-audit: * @ [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ok*'`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	matched := 0
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if auditWatermarkNoteRe.MatchString(strings.TrimSpace(body)) {
			matched++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	baselines := len(baseline)
	superseded := matched - baselines
	if superseded < 0 {
		superseded = 0 // defensive: the regexp re-parse keeps these aligned
	}
	return &auditWatermarksReadout{
		Matched:    matched,
		Baselines:  baselines,
		Superseded: superseded,
		Trigger:    auditOQ5SupersededTrigger,
		Tripped:    superseded >= auditOQ5SupersededTrigger,
	}, nil
}

func auditWatermarksCmd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("audit watermarks", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := auditWatermarksFindings(db)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(r)
	}
	fmt.Printf("watermarks: %d matched, %d baselines, %d superseded (OQ5 trigger %d)\n",
		r.Matched, r.Baselines, r.Superseded, r.Trigger)
	if r.Tripped {
		fmt.Printf("trigger-tripped: superseded watermarks (%d) >= OQ5 reopen threshold (%d) — see docs/22 §10 OQ5\n",
			r.Superseded, r.Trigger)
	}
	return nil
}

// auditShortHash returns the 7-hex prefix of a blob hash (substr(hash,1,7)),
// matching the watermark format; a too-short hash is returned as-is.
func auditShortHash(hash string) string {
	if len(hash) >= 7 {
		return hash[:7]
	}
	return hash
}

// auditNumberedH2 counts the numbered top-level sections in a stored outline —
// "## N. Title" / "## N Title" lines — the denominator for the §N anchor check.
func auditNumberedH2(headings string) int {
	n := 0
	for _, h := range strings.Split(headings, "\n") {
		h = strings.TrimSpace(h)
		if !strings.HasPrefix(h, "## ") {
			continue
		}
		rest := strings.TrimSpace(h[3:])
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i > 0 {
			n++
		}
	}
	return n
}

// auditAnchorIndex extracts the leading section number from a "§N" citation
// fragment, returning it and whether the fragment carried one.
func auditAnchorIndex(section string) (int, bool) {
	m := auditAnchorRe.FindStringSubmatch(section)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// --- stuck ---------------------------------------------------------------

// auditStuckTask is one stuck-task finding: the task and how long it has been in
// its stuck condition (a held lock or an idle in-progress claim).
type auditStuckTask struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	LockedBy string `json:"locked_by,omitempty"`
	AgeSecs  int64  `json:"age_secs"`
}

// auditStuckWorktree is a worktree-registry row that should have been cleaned
// up: its task is already done, or its path no longer exists on disk.
type auditStuckWorktree struct {
	Path   string `json:"path"`
	TaskID string `json:"task_id"`
	Branch string `json:"branch,omitempty"`
	Reason string `json:"reason"` // task-done | missing-path
}

// auditStuck is the `audit stuck` findings: held-too-long locks, orphaned
// in-progress tasks, and worktree rows whose cleanup was skipped.
type auditStuck struct {
	StaleLocks       []auditStuckTask     `json:"stale_locks"`
	IdleInProgress   []auditStuckTask     `json:"idle_in_progress"`
	DoneWorktrees    []auditStuckWorktree `json:"done_worktrees"`
	MissingWorktrees []auditStuckWorktree `json:"missing_worktrees"`
}

func auditStuckCmd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("audit stuck", flag.ContinueOnError)
	age := fs.Duration("age", 24*time.Hour, "flag unlocked in-progress tasks idle longer than this")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := auditStuckFindings(db, *age)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(s)
	}
	for _, t := range s.StaleLocks {
		fmt.Printf("stale-lock: [%s] %s — held by %s for %s\n", t.ID, t.Title, t.LockedBy, auditDur(t.AgeSecs))
	}
	for _, t := range s.IdleInProgress {
		fmt.Printf("idle-in-progress: [%s] %s — unlocked, idle %s\n", t.ID, t.Title, auditDur(t.AgeSecs))
	}
	for _, w := range s.DoneWorktrees {
		fmt.Printf("worktree-leak: %s (task %s is done)\n", w.Path, w.TaskID)
	}
	for _, w := range s.MissingWorktrees {
		fmt.Printf("worktree-missing: %s (task %s, path gone)\n", w.Path, w.TaskID)
	}
	return nil
}

// auditStuckFindings collects stale locks (held past staleLockThreshold),
// unlocked in-progress tasks idle longer than age, and worktree-registry rows
// whose task is done or whose path is gone. Shared by `audit stuck` and
// `audit all`. The lock/idle ages derive from updated_at (locked_at for held
// locks); the worktree path check stats the filesystem.
func auditStuckFindings(db *sql.DB, age time.Duration) (*auditStuck, error) {
	out := &auditStuck{
		StaleLocks:       []auditStuckTask{},
		IdleInProgress:   []auditStuckTask{},
		DoneWorktrees:    []auditStuckWorktree{},
		MissingWorktrees: []auditStuckWorktree{},
	}
	now := time.Now()

	// Stale locks: held longer than staleLockThreshold (reuse the reap default).
	lockCutoff := timeToMs(now.Add(-staleLockThreshold))
	lrows, err := db.Query(
		`SELECT id, title, locked_by, locked_at FROM tasks
		WHERE locked_by IS NOT NULL AND locked_at < ? ORDER BY locked_at`,
		lockCutoff,
	)
	if err != nil {
		return nil, err
	}
	for lrows.Next() {
		var id, title string
		var lockedBy sql.NullString
		var lockedAt sql.NullInt64
		if err := lrows.Scan(&id, &title, &lockedBy, &lockedAt); err != nil {
			lrows.Close()
			return nil, err
		}
		out.StaleLocks = append(out.StaleLocks, auditStuckTask{
			ID: id, Title: title, LockedBy: lockedBy.String,
			AgeSecs: int64(now.Sub(msToTime(lockedAt.Int64)).Seconds()),
		})
	}
	lrows.Close()
	if err := lrows.Err(); err != nil {
		return nil, err
	}

	// Orphaned in-progress: unlocked but still in-progress (the agent died after
	// unlocking but before a release), idle longer than --age by updated_at.
	idleCutoff := timeToMs(now.Add(-age))
	irows, err := db.Query(
		`SELECT id, title, updated_at FROM tasks
		WHERE status='in-progress' AND locked_by IS NULL AND updated_at < ? ORDER BY updated_at`,
		idleCutoff,
	)
	if err != nil {
		return nil, err
	}
	for irows.Next() {
		var id, title string
		var updatedMs int64
		if err := irows.Scan(&id, &title, &updatedMs); err != nil {
			irows.Close()
			return nil, err
		}
		out.IdleInProgress = append(out.IdleInProgress, auditStuckTask{
			ID: id, Title: title, AgeSecs: int64(now.Sub(msToTime(updatedMs)).Seconds()),
		})
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return nil, err
	}

	// Worktree leaks: a row whose task is done (forgot cleanup) or whose path is
	// gone (crashed/hand-removed). The done check joins tasks; the path check
	// stats disk.
	wrows, err := db.Query(
		`SELECT w.path, w.task_id, w.branch, t.status
		FROM worktrees w LEFT JOIN tasks t ON t.id = w.task_id ORDER BY w.path`,
	)
	if err != nil {
		return nil, err
	}
	for wrows.Next() {
		var path, taskID, branch string
		var status sql.NullString
		if err := wrows.Scan(&path, &taskID, &branch, &status); err != nil {
			wrows.Close()
			return nil, err
		}
		if status.Valid && isTerminalStatus(status.String) {
			reason := "task-done"
			if status.String == string(StatusDropped) {
				reason = "task-dropped"
			}
			out.DoneWorktrees = append(out.DoneWorktrees, auditStuckWorktree{
				Path: path, TaskID: taskID, Branch: branch, Reason: reason,
			})
		}
		if !auditPathExists(path) {
			out.MissingWorktrees = append(out.MissingWorktrees, auditStuckWorktree{
				Path: path, TaskID: taskID, Branch: branch, Reason: "missing-path",
			})
		}
	}
	wrows.Close()
	if err := wrows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// --- dag -----------------------------------------------------------------

// auditEdge is a dependency edge that points at a task ID that does not exist —
// a dangling dependency thaw never validates.
type auditEdge struct {
	TaskID    string `json:"task_id"`
	DependsOn string `json:"depends_on"`
}

// auditTaskRef is a task identified by id+title in a dag finding (stale epics,
// unsourced tasks).
type auditTaskRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// auditBadSource is a Sources: citation in a task body that resolves to no doc
// on disk (a typo or a renamed doc).
type auditBadSource struct {
	TaskID  string `json:"task_id"`
	DocPath string `json:"doc_path"`
}

// auditPoison is a task with three or more failed runs — a likely-unworkable
// item a curator should re-scope or block (docs/22 §6: discarded counts).
type auditPoison struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Failures int    `json:"failures"`
}

// auditRoot is one workstream root and its ready-task count; starved is set when
// a root with open descendants has nothing dispatchable (an entrypoint stall).
type auditRoot struct {
	Root    string `json:"root"`
	Title   string `json:"title"`
	Ready   int    `json:"ready"`
	Starved bool   `json:"starved"`
}

// auditDag is the `audit dag` findings: the DAG-shape defects thaw never
// re-validates, plus per-root ready accounting.
type auditDag struct {
	Cycles      [][]string       `json:"cycles"`
	MissingDeps []auditEdge      `json:"missing_deps"`
	StaleEpics  []auditTaskRef   `json:"stale_epics"`
	Unsourced   []auditTaskRef   `json:"unsourced"`
	BadSources  []auditBadSource `json:"bad_sources"`
	Poison      []auditPoison    `json:"poison"`
	Roots       []auditRoot      `json:"roots"`
}

// auditPoisonStatusList is the run-status failure set for poison detection: a
// task with >=3 runs in these states is unlikely to complete unaided (docs/22
// §6 — discarded is the anti-fabrication verdict and counts). It is the literal
// the poison query's IN-clause is built from, so the set lives in one place.
const auditPoisonStatusList = `'error','timeout','killed','discarded','stuck'`

func auditDagCmd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("audit dag", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := auditDagFindings(db)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(d)
	}
	for _, c := range d.Cycles {
		fmt.Printf("cycle: %s\n", strings.Join(c, " → "))
	}
	for _, e := range d.MissingDeps {
		fmt.Printf("missing-dep: task %s depends on nonexistent %s\n", e.TaskID, e.DependsOn)
	}
	for _, t := range d.StaleEpics {
		fmt.Printf("stale-epic: [%s] %s — all children done, epic is not\n", t.ID, t.Title)
	}
	for _, t := range d.Unsourced {
		fmt.Printf("unsourced: [%s] %s — no Sources: line\n", t.ID, t.Title)
	}
	for _, b := range d.BadSources {
		fmt.Printf("bad-source: task %s cites nonexistent %s\n", b.TaskID, b.DocPath)
	}
	for _, p := range d.Poison {
		fmt.Printf("poison: [%s] %s — %d failed runs\n", p.ID, p.Title, p.Failures)
	}
	for _, r := range d.Roots {
		if r.Starved {
			fmt.Printf("starved-root: [%s] %s — 0 ready tasks\n", r.Root, r.Title)
		}
	}
	return nil
}

// auditDagFindings re-validates everything thaw never checks: cycles, deps on
// missing IDs, all-done epics still open, tasks without a Sources: line,
// Sources citing nonexistent docs, poison tasks, and per-workstream-root ready
// counts with a starvation flag. Shared by `audit dag` and `audit all`.
func auditDagFindings(db *sql.DB) (*auditDag, error) {
	out := &auditDag{
		Cycles:      [][]string{},
		MissingDeps: []auditEdge{},
		StaleEpics:  []auditTaskRef{},
		Unsourced:   []auditTaskRef{},
		BadSources:  []auditBadSource{},
		Poison:      []auditPoison{},
		Roots:       []auditRoot{},
	}

	// Load every task once: id, title, status, parent, body — the dag checks all
	// run off this snapshot plus the edge map.
	type taskRow struct {
		id, title, status, parent, body string
	}
	tasks := map[string]*taskRow{}
	var order []string
	trows, err := db.Query(`SELECT id, title, status, parent_id, body FROM tasks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for trows.Next() {
		var r taskRow
		var parent sql.NullString
		if err := trows.Scan(&r.id, &r.title, &r.status, &parent, &r.body); err != nil {
			trows.Close()
			return nil, err
		}
		r.parent = parent.String
		tasks[r.id] = &r
		order = append(order, r.id)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}

	edges, err := loadAllDeps(db)
	if err != nil {
		return nil, err
	}

	// Cycles + missing deps. A cycle through edge (id → dep) shows when dep can
	// reach id along depends_on edges; depPath returns the readable chain. Each
	// cycle is reported once via a canonical-key dedupe.
	seenCycle := map[string]bool{}
	for _, id := range order {
		for _, dep := range edges[id] {
			if _, ok := tasks[dep]; !ok {
				out.MissingDeps = append(out.MissingDeps, auditEdge{TaskID: id, DependsOn: dep})
				continue
			}
			path, err := depPath(db, dep, id)
			if err != nil {
				return nil, err
			}
			if path != nil {
				if key := auditCycleKey(path); !seenCycle[key] {
					seenCycle[key] = true
					out.Cycles = append(out.Cycles, path)
				}
			}
		}
	}

	// Children index: parent ID → its children's statuses (for the epic check).
	children := map[string][]string{}
	for _, id := range order {
		if p := tasks[id].parent; p != "" {
			children[p] = append(children[p], id)
		}
	}

	for _, id := range order {
		t := tasks[id]
		kids := children[id]
		// Stale epic: has children, all of them TERMINAL (done or dropped), but
		// the epic itself is not yet terminal — it should be closed/dropped too.
		if len(kids) > 0 && !isTerminalStatus(t.status) {
			allTerminal := true
			for _, c := range kids {
				if !isTerminalStatus(tasks[c].status) {
					allTerminal = false
					break
				}
			}
			if allTerminal {
				out.StaleEpics = append(out.StaleEpics, auditTaskRef{ID: id, Title: t.title})
			}
		}
		// Unsourced: no Sources: line at all. Containers (epics) are exempt —
		// only leaf work items must cite a doc.
		if len(kids) == 0 && !auditHasSourcesLine(t.body) {
			out.Unsourced = append(out.Unsourced, auditTaskRef{ID: id, Title: t.title})
		}
	}

	// Bad sources: a Sources: fragment that LOOKS like a doc citation
	// ("doc NN" / "docs/NN-….md") but resolves to no file on disk. parseSources
	// silently drops these (they never reach task_sources), so the unresolvable
	// doc-shaped fragments are re-derived here and surfaced. A non-doc fragment
	// like "D18" (a decision number) does not match the citation shape and is
	// left alone — it is not a doc-path claim.
	for _, id := range order {
		for _, frag := range auditBadDocCitations(tasks[id].body) {
			out.BadSources = append(out.BadSources, auditBadSource{TaskID: id, DocPath: frag})
		}
	}

	// Poison: tasks with >=3 runs in the failure set (auditPoisonStatusList).
	prows, err := db.Query(
		`SELECT task_id, COUNT(*) FROM agent_runs WHERE status IN (` + auditPoisonStatusList + `)
		GROUP BY task_id HAVING COUNT(*) >= 3 ORDER BY task_id`,
	)
	if err != nil {
		return nil, err
	}
	for prows.Next() {
		var taskID string
		var n int
		if err := prows.Scan(&taskID, &n); err != nil {
			prows.Close()
			return nil, err
		}
		title := ""
		if t, ok := tasks[taskID]; ok {
			title = t.title
		}
		out.Poison = append(out.Poison, auditPoison{ID: taskID, Title: title, Failures: n})
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return nil, err
	}

	// Per-workstream-root ready counts. Walk parent_id to the root for every
	// task; a ready task (open, unlocked, deps done, no children) credits its
	// root. A root with open descendants but zero ready tasks is starved.
	rootOf := func(id string) string {
		seen := map[string]bool{}
		for {
			t, ok := tasks[id]
			if !ok || t.parent == "" || seen[id] {
				return id
			}
			seen[id] = true
			id = t.parent
		}
	}
	ready, err := auditReadyIDs(db)
	if err != nil {
		return nil, err
	}
	readyByRoot := map[string]int{}
	openByRoot := map[string]bool{}
	for _, id := range order {
		root := rootOf(id)
		if tasks[id].status == string(StatusOpen) || tasks[id].status == string(StatusInProgress) {
			openByRoot[root] = true
		}
		if ready[id] {
			readyByRoot[root]++
		}
	}
	for _, id := range order {
		if tasks[id].parent != "" {
			continue // roots only
		}
		r := auditRoot{Root: id, Title: tasks[id].title, Ready: readyByRoot[id]}
		if r.Ready == 0 && openByRoot[id] {
			r.Starved = true
		}
		out.Roots = append(out.Roots, r)
	}
	return out, nil
}

// auditCycleKey returns a rotation-stable key for a cycle path so the same loop
// reported from different entry points dedupes to one finding. The path's last
// element equals its first (a closed loop); we key on the sorted member set.
func auditCycleKey(path []string) string {
	members := append([]string(nil), path...)
	sort.Strings(members)
	return strings.Join(members, "|")
}

// auditReadyIDs returns the set of task IDs that are dispatchable now, reusing
// readyWhere verbatim so "ready" means exactly what `task list --ready` and
// `task claim` mean.
func auditReadyIDs(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`SELECT t.id FROM tasks t WHERE ` + readyWhere)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// --- all -----------------------------------------------------------------

// auditWorkstream is the grouping index `audit all` adds: a workstream root and
// how many findings touch its subtree, so a curation runner can fan out one
// agent per root.
type auditWorkstream struct {
	Root     string `json:"root"`
	Title    string `json:"title"`
	Findings int    `json:"findings"`
}

// auditReport is the `audit all --json` payload: the three audits concatenated
// plus a workstream-root grouping index. THIS SHAPE IS THE INPUT CONTRACT FOR
// .claude/workflows/ (docs/22 §7); see the file-header comment for the full key
// list and do not rename fields without updating the consuming runners.
type auditReport struct {
	Drift       *auditDrift       `json:"drift"`
	Stuck       *auditStuck       `json:"stuck"`
	Dag         *auditDag         `json:"dag"`
	Workstreams []auditWorkstream `json:"workstreams"`
}

func auditAllCmd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("audit all", flag.ContinueOnError)
	age := fs.Duration("age", 24*time.Hour, "stuck: flag unlocked in-progress idle longer than this")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	drift, err := auditDriftFindings(db)
	if err != nil {
		return err
	}
	stuck, err := auditStuckFindings(db, *age)
	if err != nil {
		return err
	}
	dag, err := auditDagFindings(db)
	if err != nil {
		return err
	}
	rep := &auditReport{
		Drift: drift, Stuck: stuck, Dag: dag,
		Workstreams: auditGroupByRoot(db, drift, stuck, dag),
	}
	if *asJSON {
		return printJSON(rep)
	}
	// Plain mode reuses each verb's printer by re-dispatching the structs.
	if err := auditPrintDrift(drift); err != nil {
		return err
	}
	if err := auditPrintStuck(stuck); err != nil {
		return err
	}
	auditPrintDag(dag)
	for _, w := range rep.Workstreams {
		if w.Findings > 0 {
			fmt.Printf("workstream [%s] %s — %d findings\n", w.Root, w.Title, w.Findings)
		}
	}
	return nil
}

// auditGroupByRoot tallies, per workstream root, how many findings touch a task
// in that root's subtree — the grouping a curation runner fans out over. Drift
// findings without a task (per-doc state) are not attributed to a root;
// task-bearing findings (dangling/broken citations, stuck tasks, dag defects)
// are. A best-effort tally: a finding whose task can't be placed is skipped.
func auditGroupByRoot(db *sql.DB, d *auditDrift, s *auditStuck, g *auditDag) []auditWorkstream {
	parent, title, err := auditParentIndex(db)
	if err != nil {
		// Grouping is an index over the same data; on a query error fall back to
		// an empty grouping rather than failing the whole report.
		return []auditWorkstream{}
	}
	rootOf := func(id string) string {
		seen := map[string]bool{}
		for {
			p, ok := parent[id]
			if !ok || p == "" || seen[id] {
				return id
			}
			seen[id] = true
			id = p
		}
	}
	count := map[string]int{}
	credit := func(taskID string) {
		if taskID == "" {
			return
		}
		count[rootOf(taskID)]++
	}
	for _, l := range d.DanglingLinks {
		credit(l.TaskID)
	}
	for _, a := range d.BrokenAnchors {
		credit(a.TaskID)
	}
	for _, t := range s.StaleLocks {
		credit(t.ID)
	}
	for _, t := range s.IdleInProgress {
		credit(t.ID)
	}
	for _, w := range s.DoneWorktrees {
		credit(w.TaskID)
	}
	for _, w := range s.MissingWorktrees {
		credit(w.TaskID)
	}
	for _, c := range g.Cycles {
		if len(c) > 0 {
			credit(c[0])
		}
	}
	for _, e := range g.MissingDeps {
		credit(e.TaskID)
	}
	for _, t := range g.StaleEpics {
		credit(t.ID)
	}
	for _, t := range g.Unsourced {
		credit(t.ID)
	}
	for _, b := range g.BadSources {
		credit(b.TaskID)
	}
	for _, p := range g.Poison {
		credit(p.ID)
	}
	for _, r := range g.Roots {
		if r.Starved {
			count[r.Root]++
		}
	}

	// Emit every root, sorted, including zero-finding roots so the grouping is a
	// complete index of workstreams (a runner can see "this root is clean").
	var roots []string
	for id, p := range parent {
		if p == "" {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	out := []auditWorkstream{}
	for _, root := range roots {
		out = append(out, auditWorkstream{Root: root, Title: title[root], Findings: count[root]})
	}
	return out
}

// auditParentIndex returns parent_id and title for every task, the lookup tables
// auditGroupByRoot walks to find workstream roots.
func auditParentIndex(db *sql.DB) (parent, title map[string]string, err error) {
	rows, err := db.Query(`SELECT id, parent_id, title FROM tasks`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	parent = map[string]string{}
	title = map[string]string{}
	for rows.Next() {
		var id, t string
		var p sql.NullString
		if err := rows.Scan(&id, &p, &t); err != nil {
			return nil, nil, err
		}
		parent[id] = p.String
		title[id] = t
	}
	return parent, title, rows.Err()
}

// auditPrintDrift / auditPrintStuck / auditPrintDag render each audit's plain
// (non-JSON) lines; `audit all` calls them in turn so the human output matches
// what the individual verbs print.
func auditPrintDrift(d *auditDrift) error {
	for _, doc := range d.Docs {
		switch doc.State {
		case "ok":
			continue
		case "drifted":
			fmt.Printf("drifted: %s (%s, audited %s)\n", doc.Path, doc.CurrentHash, doc.AuditedHash)
		case "never-audited":
			fmt.Printf("never-audited: %s (%s)\n", doc.Path, doc.CurrentHash)
		}
	}
	for _, l := range d.DanglingLinks {
		fmt.Printf("dangling: task %s cites missing %s\n", l.TaskID, l.DocPath)
	}
	for _, a := range d.BrokenAnchors {
		fmt.Printf("broken-anchor: task %s cites %s %s (doc has %d numbered sections)\n", a.TaskID, a.DocPath, a.Section, a.HeadingCount)
	}
	return nil
}

func auditPrintStuck(s *auditStuck) error {
	for _, t := range s.StaleLocks {
		fmt.Printf("stale-lock: [%s] %s — held by %s for %s\n", t.ID, t.Title, t.LockedBy, auditDur(t.AgeSecs))
	}
	for _, t := range s.IdleInProgress {
		fmt.Printf("idle-in-progress: [%s] %s — unlocked, idle %s\n", t.ID, t.Title, auditDur(t.AgeSecs))
	}
	for _, w := range s.DoneWorktrees {
		fmt.Printf("worktree-leak: %s (task %s is done)\n", w.Path, w.TaskID)
	}
	for _, w := range s.MissingWorktrees {
		fmt.Printf("worktree-missing: %s (task %s, path gone)\n", w.Path, w.TaskID)
	}
	return nil
}

func auditPrintDag(d *auditDag) {
	for _, c := range d.Cycles {
		fmt.Printf("cycle: %s\n", strings.Join(c, " → "))
	}
	for _, e := range d.MissingDeps {
		fmt.Printf("missing-dep: task %s depends on nonexistent %s\n", e.TaskID, e.DependsOn)
	}
	for _, t := range d.StaleEpics {
		fmt.Printf("stale-epic: [%s] %s — all children done, epic is not\n", t.ID, t.Title)
	}
	for _, t := range d.Unsourced {
		fmt.Printf("unsourced: [%s] %s — no Sources: line\n", t.ID, t.Title)
	}
	for _, b := range d.BadSources {
		fmt.Printf("bad-source: task %s cites nonexistent %s\n", b.TaskID, b.DocPath)
	}
	for _, p := range d.Poison {
		fmt.Printf("poison: [%s] %s — %d failed runs\n", p.ID, p.Title, p.Failures)
	}
	for _, r := range d.Roots {
		if r.Starved {
			fmt.Printf("starved-root: [%s] %s — 0 ready tasks\n", r.Root, r.Title)
		}
	}
}

// auditDur formats an age in whole seconds as a compact h/m/s duration for the
// plain-text lines.
func auditDur(secs int64) string {
	return (time.Duration(secs) * time.Second).Round(time.Second).String()
}

// auditPathExists reports whether a worktree-registry path is still present on
// disk; a stat error (any kind) is treated as "gone" — the row should be
// pruned regardless of why the path is unreachable.
func auditPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// auditHasSourcesLine reports whether a task body carries any Sources: line,
// reusing the shared docSourcesLineRe (sources.go). A task with the line but
// only unresolvable citations is "sourced" for the unsourced check — its bad
// citations surface separately under bad_sources.
func auditHasSourcesLine(body string) bool {
	return docSourcesLineRe.MatchString(body)
}

// auditBadDocCitations returns the raw fragments of a task body's last Sources:
// line that look like a doc citation ("doc NN" / "docs/NN-….md") but resolve to
// no file on disk — the doc-path-claim-but-missing case `audit dag` reports.
// It mirrors parseSources's fragment walk but keeps the unresolvable doc-shaped
// ones instead of dropping them; non-doc fragments (e.g. "D18") never match the
// citation shape and are not returned.
func auditBadDocCitations(body string) []string {
	m := docSourcesLineRe.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		return nil
	}
	line := m[len(m)-1][1] // the last Sources: line wins, as in parseSources
	var bad []string
	for _, frag := range strings.Split(line, ";") {
		frag = strings.TrimSpace(frag)
		if frag == "" {
			continue
		}
		c := docCitationRe.FindStringSubmatch(frag)
		if c == nil {
			continue // not a doc-shaped citation (e.g. "D18"); not a path claim
		}
		var path string
		if c[1] != "" {
			path = docSourceResolveLiteral(c[1])
		} else {
			path = docSourceResolveNumber(c[2])
		}
		if path == "" {
			// Matched the doc-citation shape but no docs/NN-*.md file exists.
			bad = append(bad, strings.TrimSpace(c[0]))
		}
	}
	return bad
}
