// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The `work` command (alias `audit work`) is the Go promotion of
// scripts/taskdb/ready-work.py: it triages the `--ready` dispatch frontier into
// buckets and surfaces the SUBSTANTIVE set grouped by root epic, so a mature
// roadmap's wall of engine-generated bookkeeping doesn't drown the real work
// (see .claude/workflows/FINDING-WORK.md §1.1). Unlike the python wrapper it
// talks to the DB/lock layer DIRECTLY (no shell-out, no --json re-parse) and
// adds two things the python script cannot see:
//
//   - CONTENTION awareness: it cross-references the same live lock holders
//     `taskdb status` shows AND the .claude/worktrees/agent-* trees a parallel
//     session has checked out, flagging any ready task another session is
//     actively working (a worktree edit holds no taskdb lock, so --ready alone
//     cannot exclude it). Unregistered agent-* trees on disk — checkouts with no
//     registry row, which cannot be attributed to a ready task — are counted and
//     surfaced as an aggregate footer so they are never silently dropped.
//   - CONFIG-DRIVEN bucket keywords: the heuristics live in a table
//     (defaultBucketRules) that an operator can override via a JSON file
//     (TASKDB_WORK_BUCKETS, or scripts/taskdb/work-buckets.json) WITHOUT
//     recompiling.
//
// It is strictly READ-ONLY: SELECTs + filesystem reads, never a write or a lock.

// bucket names, in display/priority order. First matching rule wins.
const (
	bucketBookkeeping = "bookkeeping"
	bucketGated       = "gated"
	bucketStrategic   = "strategic"
	bucketDocs        = "docs"
	bucketSubstantive = "substantive"
)

// bucketScope selects which text a rule matches against: the title only (for the
// engine-generated "re-scope files-overlap:" prefix, which must not be triggered
// by an incidental body mention) or the title+body haystack.
type bucketScope string

const (
	scopeTitle bucketScope = "title"
	scopeBody  bucketScope = "body" // title + body
)

// bucketRule is one config-driven classification rule: a bucket label, the text
// scope to match, and the (case-insensitive) regex alternatives that select it.
// The literal `Patterns` are the tunable surface — an operator edits these in
// JSON, never the Go source, to retune the heuristic.
type bucketRule struct {
	Bucket   string      `json:"bucket"`
	Scope    bucketScope `json:"scope"`
	Patterns []string    `json:"patterns"`

	re *regexp.Regexp // compiled from Patterns; nil until compile()
}

// defaultBucketRules carries over ready-work.py's BOOKKEEPING/GATED/STRATEGIC/DOCS
// regexes VERBATIM in behavior, as a table. Order is load-bearing: first match
// wins, exactly like the python `classify()` (bookkeeping → gated → strategic →
// docs → else substantive). Anything no rule matches is substantive.
var defaultBucketRules = []bucketRule{
	{
		Bucket: bucketBookkeeping,
		Scope:  scopeTitle,
		// ^\s*re-scope files-overlap:   (title only, anchored — engine defer noise)
		Patterns: []string{`^\s*re-scope files-overlap:`},
	},
	{
		Bucket: bucketGated,
		Scope:  scopeBody,
		Patterns: []string{
			`\bDS_PG_DSN\b`,
			`\bDS_[A-Z0-9_]*_LIVE\b`,
			`\blive[- ]?pg\b`,
			`\blive[- ]?CI\b`,
			`\bCI run\b`,
			`\[human\]`,
			`MANUAL OPERATOR`,
			`\bproto[- ]?freeze`,
			`RoleCatalog proto`,
			`once\s+NFT-?\d`,
			`once\s+.{0,40}\blands\b`,
			`pending\s+.{0,50}(seed|policy[- ]?push|freeze)`,
			`requires\s+.{0,50}\blanded\b`,
			`blocked:\s*prot`,
			`DS_E2E_LIVE`,
		},
	},
	{
		Bucket: bucketStrategic,
		Scope:  scopeBody,
		Patterns: []string{
			`\bbuild-vs-buy\b`,
			`\bratif`,
			`\bM2-gated\b`,
			`\bevaluate\b`,
			`\bdecide the\b`,
			`\bdecide\b\s+the`,
			`coordinate\s+.{0,40}\bbefore\b`,
			`\bcounsel\b`,
			`\blegal\b`,
			`\badoption\b`,
			`entity-structure`,
			`\bobligation`,
		},
	},
	{
		Bucket: bucketDocs,
		Scope:  scopeBody,
		Patterns: []string{
			`\bgofmt\b`,
			`micro-?benchmark`,
			`allocs[- ]?gate`,
			`e2e pin`,
			`\bcitation\b`,
			`\bnarrative\b`,
			`docstring`,
			`comment-only`,
			`\btypo\b`,
			`wave-note`,
			`\brephrase\b`,
			`\bannotate\b`,
			`\bREADME\b`,
			`\brunbook\b`,
			`single-source`,
			`\bre-cite\b`,
		},
	},
}

// compile builds the case-insensitive alternation regex for a rule. An empty
// pattern list yields a rule that never matches (rather than an error), so an
// operator can disable a bucket by clearing its patterns in the config.
func (r *bucketRule) compile() error {
	if len(r.Patterns) == 0 {
		r.re = nil
		return nil
	}
	re, err := regexp.Compile(`(?i)` + strings.Join(r.Patterns, "|"))
	if err != nil {
		return fmt.Errorf("bucket %q: bad pattern: %w", r.Bucket, err)
	}
	r.re = re
	return nil
}

// loadBucketRules returns the active rule table: the JSON override when
// TASKDB_WORK_BUCKETS (or scripts/taskdb/work-buckets.json under the repo root)
// is present and parses, else the built-in defaults. The override is a tunable
// knob — it lets the heuristic be retuned without recompiling. A malformed
// override is an error (loud, not silently-default) so a typo can't quietly
// degrade triage.
func loadBucketRules() ([]bucketRule, error) {
	path := os.Getenv("TASKDB_WORK_BUCKETS")
	if path == "" {
		if root, err := repoRoot(); err == nil {
			cand := filepath.Join(root, "scripts", "taskdb", "work-buckets.json")
			if _, err := os.Stat(cand); err == nil {
				path = cand
			}
		}
	}

	var rules []bucketRule
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read bucket config %s: %w", path, err)
		}
		if err := json.Unmarshal(b, &rules); err != nil {
			return nil, fmt.Errorf("parse bucket config %s: %w", path, err)
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("bucket config %s defines no rules", path)
		}
	} else {
		// Copy the defaults so compile() doesn't mutate the package-level table
		// across invocations (the long-lived MCP process reuses the process).
		rules = append(rules, defaultBucketRules...)
	}

	for i := range rules {
		if rules[i].Scope == "" {
			rules[i].Scope = scopeBody
		}
		if err := rules[i].compile(); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// classify returns the first bucket whose rule matches the task, or
// "substantive" when none do — mirroring ready-work.py's first-match-wins
// classify(). Title-scope rules see only the title; body-scope rules see
// "title\nbody".
func classifyTask(rules []bucketRule, t *Task) string {
	title := t.Title
	hay := title + "\n" + t.Body
	for i := range rules {
		re := rules[i].re
		if re == nil {
			continue
		}
		text := hay
		if rules[i].Scope == scopeTitle {
			text = title
		}
		if re.MatchString(text) {
			return rules[i].Bucket
		}
	}
	return bucketSubstantive
}

// workTask is a ready task plus its triage metadata: the bucket it landed in,
// its root epic, and any active contention (a lock holder and/or a worktree a
// parallel session has checked out).
type workTask struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Bucket    string   `json:"bucket"`
	Root      string   `json:"root"`
	RootTitle string   `json:"root_title,omitempty"`
	LockedBy  string   `json:"locked_by,omitempty"` // cross-session lock holder, if any
	Worktrees []string `json:"worktrees,omitempty"` // agent-* trees checked out for this task
	Contended bool     `json:"contended,omitempty"` // locked OR a worktree is mid-edit
}

// orphanTree is one on-disk .claude/worktrees/agent-* directory with no registry
// row: an unattributable parallel-session edit. Name is its basename; Mtime is
// the directory's modification time (RFC3339, UTC) and AgeSecs its age in whole
// seconds at scan time — together they let an operator judge live-vs-stale
// (a fresh mtime = a session still editing; a stale one = an abandoned checkout)
// WITHOUT a manual `ls -l`. Mtime is omitempty (absent when the dir stat failed);
// AgeSecs is always emitted (0 when unknown).
type orphanTree struct {
	Name    string `json:"name"`
	Mtime   string `json:"mtime,omitempty"`
	AgeSecs int64  `json:"age_secs"`
}

// workResult is the full triage outcome, the `--json` shape.
type workResult struct {
	Buckets map[string][]*workTask `json:"buckets"`
	// UnregisteredAgentTrees counts on-disk .claude/worktrees/agent-* directories
	// with no registry row: parallel-session edits that cannot be attributed to a
	// specific ready task but are still worth a manual glance.
	UnregisteredAgentTrees int `json:"unregistered_agent_trees,omitempty"`
	// UnregisteredAgentTreeNames carries those same on-disk agent-* trees, sorted
	// by basename, so the operator no longer has to `ls .claude/worktrees` to learn
	// WHICH trees are orphaned. Each entry is an orphanTree {name, mtime, age_secs}
	// (the shape changed from a bare []string when per-orphan mtime/age was added —
	// see README) so live-vs-stale is legible from --json alone. It NAMES the trees
	// without attributing any of them to a task (the no-guess invariant):
	// len == UnregisteredAgentTrees. The human footer caps its inline list; the
	// FULL set (with mtime/age) always rides here.
	UnregisteredAgentTreeNames []orphanTree `json:"unregistered_agent_tree_names,omitempty"`
}

func cmdWork(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("work", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable {buckets: {bucket: [tasks]}}")
	showAll := fs.Bool("all", false, "include the bookkeeping bucket in the default view")
	onlySub := fs.Bool("substantive", false, "show ONLY substantive (hide docs too)")
	tag := fs.String("tag", "", "list a single set-aside bucket (gated|strategic|docs|bookkeeping|substantive)")
	epic := fs.String("epic", "", "restrict to one root-epic id (prefix-matched)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rules, err := loadBucketRules()
	if err != nil {
		return err
	}

	// Pull the full task set once: we need it for parent_id → root-epic walking
	// and for epic-title display. by_id mirrors ready-work.py's by_id map.
	all, err := loadAllTasks(db)
	if err != nil {
		return err
	}
	byID := make(map[string]*Task, len(all))
	for _, t := range all {
		byID[t.ID] = t
	}

	// Contention sources, read DIRECTLY (not via shelling out to `taskdb status`
	// / `ls`): the live lock holders and the agent-* worktree checkouts.
	lockBy := lockHolders(db)
	wtByTask, unregisteredNames := agentWorktreesByTask(db)

	// The ready frontier, straight from the DB via the shared readyWhere clause —
	// the exact set `task list --ready` returns.
	ready, err := readyTasks(db)
	if err != nil {
		return err
	}

	// Bucketize, attaching root epic + contention to each ready task.
	buckets := map[string][]*workTask{
		bucketSubstantive: {}, bucketDocs: {}, bucketGated: {},
		bucketStrategic: {}, bucketBookkeeping: {},
	}
	for _, t := range ready {
		root := rootEpic(byID, t.ID)
		if *epic != "" && !strings.HasPrefix(root, strings.ToUpper(*epic)) {
			continue
		}
		wt := &workTask{
			ID:        t.ID,
			Title:     t.Title,
			Bucket:    classifyTask(rules, t),
			Root:      root,
			Worktrees: wtByTask[t.ID],
		}
		if rt, ok := byID[root]; ok {
			wt.RootTitle = rt.Title
		}
		if holder, ok := lockBy[t.ID]; ok {
			wt.LockedBy = holder
		}
		wt.Contended = wt.LockedBy != "" || len(wt.Worktrees) > 0
		buckets[wt.Bucket] = append(buckets[wt.Bucket], wt)
	}

	if *asJSON {
		return printJSON(workResult{
			Buckets:                    buckets,
			UnregisteredAgentTrees:     len(unregisteredNames),
			UnregisteredAgentTreeNames: unregisteredNames,
		})
	}
	if *tag != "" {
		return printWorkTag(buckets, *tag)
	}
	return printWorkDefault(buckets, *onlySub, *showAll, unregisteredNames)
}

// printWorkTag lists one set-aside bucket, mirroring `ready-work.py --tag`.
func printWorkTag(buckets map[string][]*workTask, tag string) error {
	rows, ok := buckets[tag]
	if !ok {
		return fmt.Errorf("unknown bucket %q (want: substantive|docs|gated|strategic|bookkeeping)", tag)
	}
	fmt.Printf("=== %s: %d ready ===\n", tag, len(rows))
	for _, t := range rows {
		fmt.Printf("  %-12s  %s%s\n", short(t.ID, 12), trunc(t.Title, 80), contentionTag(t))
	}
	return nil
}

// printWorkDefault renders substantive (+ docs unless --substantive) grouped by
// root epic, with a one-line tally of the set-aside buckets — mirroring
// ready-work.py's default view, plus a contention annotation per task.
func printWorkDefault(buckets map[string][]*workTask, onlySub, showAll bool, unregisteredNames []orphanTree) error {
	show := []string{bucketSubstantive}
	if !onlySub {
		show = append(show, bucketDocs)
	}

	shown := 0
	contended := 0
	for _, bucket := range show {
		rows := buckets[bucket]
		if len(rows) == 0 {
			continue
		}
		hdr := "SUBSTANTIVE"
		if bucket == bucketDocs {
			hdr = "DOCS / low-blast polish"
		}
		fmt.Printf("\n========== %s: %d ready ==========\n", hdr, len(rows))

		// Group by root epic, ordered by group size descending (largest first),
		// matching ready-work.py's sort.
		groups := map[string][]*workTask{}
		var order []string
		for _, t := range rows {
			if _, seen := groups[t.Root]; !seen {
				order = append(order, t.Root)
			}
			groups[t.Root] = append(groups[t.Root], t)
		}
		sort.SliceStable(order, func(i, j int) bool {
			return len(groups[order[i]]) > len(groups[order[j]])
		})
		for _, root := range order {
			grp := groups[root]
			rootTitle := "?"
			if len(grp) > 0 && grp[0].RootTitle != "" {
				rootTitle = grp[0].RootTitle
			}
			fmt.Printf("\n  ▸ %s  [%s]  (%d)\n", trunc(rootTitle, 64), short(root, 12), len(grp))
			for _, t := range grp {
				fmt.Printf("      %-12s  %s%s\n", short(t.ID, 12), trunc(t.Title, 72), contentionTag(t))
				shown++
				if t.Contended {
					contended++
				}
			}
		}
	}

	if showAll && len(buckets[bucketBookkeeping]) > 0 {
		fmt.Printf("\n========== BOOKKEEPING (engine re-scope noise): %d ==========\n", len(buckets[bucketBookkeeping]))
		for _, t := range buckets[bucketBookkeeping] {
			fmt.Printf("      %-12s  %s\n", short(t.ID, 12), trunc(t.Title, 72))
		}
	}

	docsTally := ""
	if onlySub {
		docsTally = fmt.Sprintf("docs=%d ", len(buckets[bucketDocs]))
	}
	contendedTally := ""
	if contended > 0 {
		contendedTally = fmt.Sprintf("⚠ %d of these are CONTENDED (locked or a worktree is mid-edit) — see the markers. ", contended)
	}
	fmt.Printf("\n--- %d shown | %sset aside: gated=%d strategic=%d %sbookkeeping=%d "+
		"(inspect: --tag gated|strategic|docs|bookkeeping, or --all) ---\n",
		shown, contendedTally,
		len(buckets[bucketGated]), len(buckets[bucketStrategic]), docsTally, len(buckets[bucketBookkeeping]))

	if len(unregisteredNames) > 0 {
		fmt.Printf("    ⚠ %d unregistered agent-* tree(s) on disk (cannot attribute to a ready task — glance manually; full list + mtime/age in --json): %s\n",
			len(unregisteredNames), orphanFooterList(unregisteredNames))
	}

	if shown == 0 {
		fmt.Println("    (no substantive ready work — re-run `taskdb audit dag`, then consider that the")
		fmt.Println("     autonomously-dispatchable frontier may be drained: report to the human.)")
	}
	return nil
}

// maxFooterOrphans bounds how many orphan basenames the human footer lists
// inline before collapsing the tail into "and N more" — a pathological
// worktrees dir (dozens of stale checkouts) must not smear the footer across the
// terminal. The FULL set, with mtime/age, always rides `--json`.
const maxFooterOrphans = 8

// orphanFooterList renders the bounded, comma-joined basenames for the human
// footer: at most maxFooterOrphans names, then "and N more" for the remainder.
// Input is assumed name-sorted (agentWorktreesByTask guarantees it), so the
// truncation is deterministic. mtime/age are intentionally omitted here — they
// would bloat the line; the operator reads them from `--json`.
func orphanFooterList(orphans []orphanTree) string {
	names := make([]string, len(orphans))
	for i, o := range orphans {
		names[i] = o.Name
	}
	if len(names) <= maxFooterOrphans {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(names[:maxFooterOrphans], ", "), len(names)-maxFooterOrphans)
}

// contentionTag renders the inline marker a contended ready task carries: the
// cross-session lock holder and/or the agent-* worktrees mid-edit on it. Empty
// when the task is uncontended.
func contentionTag(t *workTask) string {
	if !t.Contended {
		return ""
	}
	var parts []string
	if t.LockedBy != "" {
		parts = append(parts, "locked by "+t.LockedBy)
	}
	if len(t.Worktrees) > 0 {
		parts = append(parts, "worktree: "+strings.Join(t.Worktrees, ","))
	}
	return "  ⚠ CONTENDED (" + strings.Join(parts, "; ") + ")"
}

// loadAllTasks returns every task (id/title/body/parent/status), the set
// ready-work.py fetches with `task list --json`, for root-epic resolution and
// epic-title display.
func loadAllTasks(db *sql.DB) ([]*Task, error) {
	rows, err := db.Query(`SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at FROM tasks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// readyTasks returns the dispatch frontier using the shared readyWhere clause —
// the exact set `task list --ready` returns (open, unlocked, deps done, no
// children), highest priority first.
func readyTasks(db *sql.DB) ([]*Task, error) {
	rows, err := db.Query(
		`SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at
		FROM tasks t WHERE ` + readyWhere + ` ORDER BY priority DESC, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// rootEpic walks parent_id to the top of the tree and returns the root id,
// mirroring ready-work.py's root(). A seen-set guards a corrupt cycle; a parent
// pointing outside the known set stops the walk (returns the last known id).
func rootEpic(byID map[string]*Task, id string) string {
	seen := map[string]bool{}
	cur := id
	for cur != "" {
		t, ok := byID[cur]
		if !ok {
			return cur
		}
		p := t.ParentID
		if p == "" || byID[p] == nil || seen[cur] {
			return cur
		}
		seen[cur] = true
		cur = p
	}
	return cur
}

// lockHolders returns the live taskID → holder map — the same locked_by data
// `taskdb status` surfaces (local mirror, which the lock server keeps current).
// Read-only.
func lockHolders(db *sql.DB) map[string]string {
	out := map[string]string{}
	rows, err := db.Query(`SELECT id, locked_by FROM tasks WHERE locked_by IS NOT NULL`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, by string
		if err := rows.Scan(&id, &by); err != nil {
			return out
		}
		out[id] = by
	}
	return out
}

// agentWorktreesByTask maps taskID → the agent-* worktree branch/path basenames
// a parallel session has checked out for it. It draws on BOTH signals the python
// triage tool told operators to glance at by hand:
//
//   - the taskdb worktree registry (the `worktrees` table — what `worktree list`
//     shows), filtered to live, agent-* trees;
//   - the .claude/worktrees/agent-* directories on disk (a parallel session can
//     check a tree out WITHOUT registering it, so the registry alone can miss
//     it).
//
// Both are read-only. A worktree holds NO taskdb lock, so this is the only way
// `work` can flag the contention --ready cannot exclude.
//
// The second return value is the name-sorted orphanTree entries ({name, mtime,
// age_secs}) for on-disk .claude/worktrees/agent-* directories that have NO
// registry row mapping them to a task: an unregistered tree is precisely the
// silent parallel-session edit this surface exists to flag, but it cannot be
// attributed to a specific ready row, so its basename (plus its dir mtime/age,
// so the operator can judge live-vs-stale) is reported as an honest
// un-attributed aggregate rather than guessed onto a task (the no-guess
// invariant). The count is len() of the slice.
func agentWorktreesByTask(db *sql.DB) (map[string][]string, []orphanTree) {
	out := map[string][]string{}
	var unregistered []orphanTree
	now := time.Now()
	add := func(taskID, label string) {
		if taskID == "" || label == "" {
			return
		}
		for _, e := range out[taskID] {
			if e == label {
				return
			}
		}
		out[taskID] = append(out[taskID], label)
	}

	// (a) registry rows for agent-* trees that still exist on disk.
	rows, err := db.Query(`SELECT path, task_id, branch FROM worktrees`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var path, taskID, branch string
			if err := rows.Scan(&path, &taskID, &branch); err != nil {
				break
			}
			base := filepath.Base(path)
			if !isAgentTree(base) && !isAgentTree(branch) {
				continue
			}
			if _, err := os.Stat(path); err != nil {
				continue // dead/pruned tree — no live contention
			}
			add(taskID, base)
		}
	}

	// (b) .claude/worktrees/agent-* directories on disk, mapped back to a task by
	// the registry path index (a tree present on disk but unregistered still
	// shows up as a bare directory the operator was told to `ls`).
	root, err := repoRoot()
	if err != nil {
		return out, unregistered
	}
	byPath := worktreeTaskByPath(db)
	entries, err := os.ReadDir(filepath.Join(root, ".claude", "worktrees"))
	if err != nil {
		return out, unregistered // no worktrees dir — nothing to add
	}
	for _, e := range entries {
		if !e.IsDir() || !isAgentTree(e.Name()) {
			continue
		}
		full := filepath.Join(root, ".claude", "worktrees", e.Name())
		if taskID, ok := byPath[full]; ok {
			add(taskID, e.Name())
			continue
		}
		// An unregistered agent-* tree on disk cannot be attributed to a specific
		// ready row (we never guess a task from a directory name), but it is still
		// a live parallel-session edit worth flagging — carry its basename so the
		// contention surface can NAME it (not just count it) while still keeping it
		// un-attributed to any task. The dir mtime/age (best-effort — omitted on a
		// stat failure) lets an operator judge live-vs-stale from --json alone.
		ot := orphanTree{Name: e.Name()}
		if info, ierr := e.Info(); ierr == nil {
			mt := info.ModTime()
			ot.Mtime = mt.UTC().Format(time.RFC3339)
			if age := now.Sub(mt); age > 0 {
				ot.AgeSecs = int64(age / time.Second)
			}
		}
		unregistered = append(unregistered, ot)
	}
	// deterministic order for --json + the footer (sort by basename).
	sort.Slice(unregistered, func(i, j int) bool { return unregistered[i].Name < unregistered[j].Name })
	return out, unregistered
}

// worktreeTaskByPath indexes the registry by absolute path → task_id.
func worktreeTaskByPath(db *sql.DB) map[string]string {
	out := map[string]string{}
	rows, err := db.Query(`SELECT path, task_id FROM worktrees`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var path, taskID string
		if err := rows.Scan(&path, &taskID); err != nil {
			return out
		}
		out[path] = taskID
	}
	return out
}

// isAgentTree reports whether a basename/branch denotes a parallel session's
// agent worktree (the .claude/worktrees/agent-* convention from
// FINDING-WORK.md §1.1).
func isAgentTree(name string) bool {
	return strings.HasPrefix(filepath.Base(name), "agent-")
}

// short truncates an id to n chars (the list views show a 12-char handle).
func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// trunc clips display text to n runes without ellipsis, matching the python
// `[:84]` slicing style.
func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
