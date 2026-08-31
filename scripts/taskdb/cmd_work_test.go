// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// workTestTask is a fixture row: classification reads only title+body, so the
// other columns get sane defaults.
type workTestTask struct {
	id, title, body, parent, status string
	lockedBy                        string
}

// seedWorkDB builds a temp-dir repo (.git + taskdb.sqlite seeded via the
// production initSchema) and chdirs into it, so cmdWork's repoRoot()/openDB-free
// helpers resolve against the fixture rather than the sandbox's real DB. It
// returns the live *sql.DB (read-write — we only ever read through cmdWork).
func seedWorkDB(t *testing.T, tasks []workTestTask, deps map[string][]string) (*sql.DB, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	dbFile := filepath.Join(root, "taskdb.sqlite")
	db, err := sql.Open("sqlite", dbFile+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	now := timeToMs(time.Now().UTC())
	for _, tk := range tasks {
		status := tk.status
		if status == "" {
			status = string(StatusOpen)
		}
		var parent any
		if tk.parent != "" {
			parent = tk.parent
		}
		var lockedBy any
		var lockedAt any
		if tk.lockedBy != "" {
			lockedBy = tk.lockedBy
			lockedAt = now
		}
		if _, err := db.Exec(
			`INSERT INTO tasks(id,title,body,status,priority,parent_id,locked_by,locked_at,created_at,updated_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?)`,
			tk.id, tk.title, tk.body, status, 0, parent, lockedBy, lockedAt, now, now,
		); err != nil {
			t.Fatalf("insert task %s: %v", tk.id, err)
		}
	}
	for from, tos := range deps {
		for _, to := range tos {
			if _, err := db.Exec(`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, from, to); err != nil {
				t.Fatalf("insert dep %s->%s: %v", from, to, err)
			}
		}
	}

	// cmdWork's filesystem helpers (worktree scan, bucket-config lookup) resolve
	// against CWD-anchored repoRoot(); chdir into the fixture for the test.
	wd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd); _ = db.Close() })
	return db, root
}

// triage runs cmdWork's classification + contention pipeline against the seeded
// DB and returns the bucketed result, the same structure `work --json` emits.
// It exercises the real code path (loadBucketRules → readyTasks → classify →
// contention) rather than reaching into internals.
func triage(t *testing.T, db *sql.DB) map[string][]*workTask {
	t.Helper()
	rules, err := loadBucketRules()
	if err != nil {
		t.Fatalf("loadBucketRules: %v", err)
	}
	all, err := loadAllTasks(db)
	if err != nil {
		t.Fatalf("loadAllTasks: %v", err)
	}
	byID := map[string]*Task{}
	for _, tk := range all {
		byID[tk.ID] = tk
	}
	lockBy := lockHolders(db)
	wtByTask, _ := agentWorktreesByTask(db)
	ready, err := readyTasks(db)
	if err != nil {
		t.Fatalf("readyTasks: %v", err)
	}
	out := map[string][]*workTask{}
	for _, tk := range ready {
		root := rootEpic(byID, tk.ID)
		wt := &workTask{
			ID: tk.ID, Title: tk.Title, Bucket: classifyTask(rules, tk),
			Root: root, Worktrees: wtByTask[tk.ID],
		}
		if holder, ok := lockBy[tk.ID]; ok {
			wt.LockedBy = holder
		}
		wt.Contended = wt.LockedBy != "" || len(wt.Worktrees) > 0
		out[wt.Bucket] = append(out[wt.Bucket], wt)
	}
	return out
}

func bucketIDs(buckets map[string][]*workTask, bucket string) map[string]bool {
	out := map[string]bool{}
	for _, t := range buckets[bucket] {
		out[t.ID] = true
	}
	return out
}

// TestClassifyBuckets pins the carried-over heuristics: each fixture title/body
// must land in its expected bucket, first-match-wins, and the default
// (unmatched) case is substantive.
func TestClassifyBuckets(t *testing.T) {
	rules, err := loadBucketRules()
	if err != nil {
		t.Fatalf("loadBucketRules: %v", err)
	}
	cases := []struct {
		title, body, want string
	}{
		{"re-scope files-overlap: wave-9 unit foo", "", bucketBookkeeping},
		{"run the DS_PG_DSN live migration", "", bucketGated},
		{"wire credential swap", "needs a proto-freeze first", bucketGated},
		{"[human] sign the policy push", "", bucketGated},
		{"land identity once NFT-3 lands", "", bucketGated},
		{"build-vs-buy: pick a queue", "", bucketStrategic},
		{"ratify the D80 split", "", bucketStrategic},
		{"evaluate the lock server", "", bucketStrategic},
		{"polish the README intro", "", bucketDocs},
		{"fix a typo in the runbook", "", bucketDocs},
		{"reconcile a citation", "", bucketDocs},
		{"implement the dnsgate admission txn", "real substantive code", bucketSubstantive},
		// first-match-wins: bookkeeping title beats a body that also reads gated.
		{"re-scope files-overlap: x", "this mentions DS_PG_DSN in the body", bucketBookkeeping},
		// gated (checked before docs) wins when both could match.
		{"update README", "blocked: proto-freeze pending", bucketGated},
	}
	for _, c := range cases {
		got := classifyTask(rules, &Task{Title: c.title, Body: c.body})
		if got != c.want {
			t.Errorf("classify(%q / %q) = %q, want %q", c.title, c.body, got, c.want)
		}
	}
}

// TestTriageGroupsSubstantiveByRootEpic checks the end-to-end frontier triage:
// only ready rows are bucketed, noise is set aside, and a child's root epic is
// resolved through parent_id.
func TestTriageGroupsSubstantiveByRootEpic(t *testing.T) {
	epic := "01EPIC0000000000000000000A"
	tasks := []workTestTask{
		{id: epic, title: "egress epic"}, // has a child → not itself ready
		{id: "01SUB000000000000000000001", title: "build the gateway", parent: epic},
		{id: "01SUB000000000000000000002", title: "re-scope files-overlap: noise", parent: epic},
		{id: "01DOC000000000000000000003", title: "polish the README"},
		{id: "01GAT000000000000000000004", title: "run DS_E2E_LIVE suite"},
		{id: "01DONE00000000000000000005", title: "already done", status: string(StatusDone)},
	}
	db, _ := seedWorkDB(t, tasks, nil)
	buckets := triage(t, db)

	sub := bucketIDs(buckets, bucketSubstantive)
	if !sub["01SUB000000000000000000001"] {
		t.Errorf("substantive should contain the gateway task; got %v", sub)
	}
	if sub[epic] {
		t.Errorf("epic with children must not be ready/substantive")
	}
	if sub["01DONE00000000000000000005"] {
		t.Errorf("done task must not appear in the ready frontier")
	}
	if !bucketIDs(buckets, bucketBookkeeping)["01SUB000000000000000000002"] {
		t.Errorf("re-scope files-overlap row must bucket as bookkeeping")
	}
	if !bucketIDs(buckets, bucketDocs)["01DOC000000000000000000003"] {
		t.Errorf("README row must bucket as docs")
	}
	if !bucketIDs(buckets, bucketGated)["01GAT000000000000000000004"] {
		t.Errorf("DS_E2E_LIVE row must bucket as gated")
	}
	// root-epic resolution: the substantive child reports the epic as its root.
	for _, wt := range buckets[bucketSubstantive] {
		if wt.ID == "01SUB000000000000000000001" && wt.Root != epic {
			t.Errorf("root of substantive child = %q, want %q", wt.Root, epic)
		}
	}
}

// TestContentionLockHolder flags a ready task another session holds a lock on.
// (--ready excludes LOCKED tasks, so to test the flag we read the holder map
// directly against a task whose readiness we don't gate on the lock — we assert
// the lockHolders signal and the contention derivation.)
func TestContentionLockHolder(t *testing.T) {
	tasks := []workTestTask{
		{id: "01LOCK00000000000000000001", title: "contended build", lockedBy: "sess-other"},
		{id: "01FREE00000000000000000002", title: "free build"},
	}
	db, _ := seedWorkDB(t, tasks, nil)

	holders := lockHolders(db)
	if holders["01LOCK00000000000000000001"] != "sess-other" {
		t.Fatalf("lockHolders missed the held lock: %v", holders)
	}
	if _, ok := holders["01FREE00000000000000000002"]; ok {
		t.Errorf("free task should not appear in lockHolders")
	}

	// The free task is the only ready one (locked is excluded by readyWhere);
	// it must be uncontended.
	buckets := triage(t, db)
	for _, wt := range buckets[bucketSubstantive] {
		if wt.ID == "01FREE00000000000000000002" && wt.Contended {
			t.Errorf("free task wrongly flagged contended")
		}
	}

	// Derivation: a workTask with a lock holder is contended.
	wt := &workTask{LockedBy: "sess-x"}
	wt.Contended = wt.LockedBy != "" || len(wt.Worktrees) > 0
	if !wt.Contended || contentionTag(wt) == "" {
		t.Errorf("a lock-held task must be flagged contended with a marker")
	}
}

// TestContentionWorktree flags a ready task a parallel session has checked out
// in a .claude/worktrees/agent-* tree WITHOUT taking a taskdb lock — the case
// --ready cannot see. The registry row + the on-disk tree must map back to the
// task.
func TestContentionWorktree(t *testing.T) {
	taskID := "01WT0000000000000000000001"
	tasks := []workTestTask{{id: taskID, title: "tree-contended build"}}
	db, root := seedWorkDB(t, tasks, nil)

	// Provision the on-disk agent-* tree and register it (path must exist for the
	// liveness filter to keep it).
	wtPath := filepath.Join(root, ".claude", "worktrees", "agent-7f")
	if err := os.MkdirAll(wtPath, 0o755); err != nil {
		t.Fatalf("mkdir worktree: %v", err)
	}
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO worktrees(path,task_id,branch,base_ref,created_at,last_used_at) VALUES(?,?,?,?,?,?)`,
		wtPath, taskID, "agent-7f/branch", "deadbeef", now, now,
	); err != nil {
		t.Fatalf("insert worktree: %v", err)
	}

	wtMap, _ := agentWorktreesByTask(db)
	if len(wtMap[taskID]) == 0 {
		t.Fatalf("worktree contention not detected for %s; got %v", taskID, wtMap)
	}

	buckets := triage(t, db)
	var found *workTask
	for _, wt := range buckets[bucketSubstantive] {
		if wt.ID == taskID {
			found = wt
		}
	}
	if found == nil {
		t.Fatalf("ready task %s missing from substantive bucket", taskID)
	}
	if !found.Contended {
		t.Errorf("task with an agent-* worktree must be flagged contended; tag=%q", contentionTag(found))
	}
	if contentionTag(found) == "" {
		t.Errorf("contended task must render a non-empty marker")
	}
}

// TestConfigDrivenBucketsOverride proves the keyword table is config-driven: a
// JSON override at scripts/taskdb/work-buckets.json reclassifies a task the
// defaults would call substantive, with no recompile.
func TestConfigDrivenBucketsOverride(t *testing.T) {
	tasks := []workTestTask{{id: "01CFG000000000000000000001", title: "frobnicate the widget"}}
	db, root := seedWorkDB(t, tasks, nil)

	// By default "frobnicate" is substantive.
	if got := classifyTask(mustRules(t), &Task{Title: "frobnicate the widget"}); got != bucketSubstantive {
		t.Fatalf("baseline: frobnicate = %q, want substantive", got)
	}

	cfgDir := filepath.Join(root, "scripts", "taskdb")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir cfg: %v", err)
	}
	cfg := `[{"bucket":"docs","scope":"title","patterns":["\\bfrobnicate\\b"]}]`
	if err := os.WriteFile(filepath.Join(cfgDir, "work-buckets.json"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	// Now the override file reclassifies it as docs, and the live frontier triage
	// reflects the override too.
	if got := classifyTask(mustRules(t), &Task{Title: "frobnicate the widget"}); got != bucketDocs {
		t.Errorf("override: frobnicate = %q, want docs", got)
	}
	buckets := triage(t, db)
	if !bucketIDs(buckets, bucketDocs)["01CFG000000000000000000001"] {
		t.Errorf("override config did not reclassify the ready task into docs: %+v", buckets)
	}
}

// TestMalformedConfigErrors ensures a broken override is loud, not silently
// ignored (a typo must not quietly degrade triage to defaults).
func TestMalformedConfigErrors(t *testing.T) {
	_, root := seedWorkDB(t, nil, nil)
	cfgDir := filepath.Join(root, "scripts", "taskdb")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir cfg: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "work-buckets.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	if _, err := loadBucketRules(); err == nil {
		t.Errorf("malformed bucket config must error, not fall back silently")
	}
}

func mustRules(t *testing.T) []bucketRule {
	t.Helper()
	r, err := loadBucketRules()
	if err != nil {
		t.Fatalf("loadBucketRules: %v", err)
	}
	return r
}

// TestUnregisteredAgentTrees pins the honesty gap: an on-disk
// .claude/worktrees/agent-* directory with no registry row is an
// unattributable parallel-session edit that must be NAMED (never silently
// dropped), while registered agent-* trees still attribute to their task with
// no double-count. Table-driven over several K-registered / M-unregistered
// shapes; asserts the returned basenames == the sorted on-disk dirs, that all
// N basenames emit in BOTH the --json output and the footer, and that
// registered trees are NOT listed among the unregistered names.
func TestUnregisteredAgentTrees(t *testing.T) {
	cases := []struct{ registered, unregistered int }{
		{registered: 0, unregistered: 0},
		{registered: 0, unregistered: 3},
		{registered: 2, unregistered: 0},
		{registered: 2, unregistered: 4},
	}
	for _, tc := range cases {
		tc := tc
		name := fmt.Sprintf("reg%d_unreg%d", tc.registered, tc.unregistered)
		t.Run(name, func(t *testing.T) {
			// One ready task per registered tree so attribution has a target.
			var tasks []workTestTask
			for i := 0; i < tc.registered; i++ {
				tasks = append(tasks, workTestTask{
					id:    fmt.Sprintf("01REG%021d", i),
					title: fmt.Sprintf("registered-tree task %d", i),
				})
			}
			db, root := seedWorkDB(t, tasks, nil)
			wtDir := filepath.Join(root, ".claude", "worktrees")
			if err := os.MkdirAll(wtDir, 0o755); err != nil {
				t.Fatalf("mkdir worktrees: %v", err)
			}
			now := timeToMs(time.Now().UTC())

			// Registered agent-* trees: on-disk dir + a registry row mapping it to
			// its task.
			var regNames []string
			for i := 0; i < tc.registered; i++ {
				name := fmt.Sprintf("agent-reg%d", i)
				regNames = append(regNames, name)
				full := filepath.Join(wtDir, name)
				if err := os.MkdirAll(full, 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", name, err)
				}
				taskID := fmt.Sprintf("01REG%021d", i)
				if _, err := db.Exec(
					`INSERT INTO worktrees(path,task_id,branch,base_ref,created_at,last_used_at) VALUES(?,?,?,?,?,?)`,
					full, taskID, name+"/branch", "deadbeef", now, now,
				); err != nil {
					t.Fatalf("insert worktree %s: %v", name, err)
				}
			}
			// Unregistered agent-* trees: on-disk dir ONLY, no registry row. Build
			// the sorted expected-names set as we go.
			var wantUnreg []string
			for i := 0; i < tc.unregistered; i++ {
				dir := fmt.Sprintf("agent-unreg%d", i)
				wantUnreg = append(wantUnreg, dir)
				if err := os.MkdirAll(filepath.Join(wtDir, dir), 0o755); err != nil {
					t.Fatalf("mkdir unreg %d: %v", i, err)
				}
			}
			sort.Strings(wantUnreg)
			// A non-agent directory must be ignored by both signals.
			if err := os.MkdirAll(filepath.Join(wtDir, "scratch-notes"), 0o755); err != nil {
				t.Fatalf("mkdir scratch: %v", err)
			}

			byTask, unregistered := agentWorktreesByTask(db)
			// The basenames must equal the sorted on-disk unregistered dirs — no more,
			// no less — and must be returned in sorted order for determinism.
			if !reflect.DeepEqual(orphanNames(unregistered), wantUnreg) {
				t.Errorf("unregistered names = %v, want %v", orphanNames(unregistered), wantUnreg)
			}
			if len(unregistered) != tc.unregistered {
				t.Errorf("unregistered count = %d, want %d", len(unregistered), tc.unregistered)
			}
			// Registered trees must NOT leak into the unregistered names (no-guess
			// invariant: a registered tree is attributed, never re-listed as orphan).
			for _, rn := range regNames {
				for _, un := range unregistered {
					if un.Name == rn {
						t.Errorf("registered tree %q wrongly listed as unregistered", rn)
					}
				}
			}
			// Registered attribution unchanged: each registered task maps to exactly
			// its one tree, and no unregistered dir leaks into the map.
			attributed := 0
			for i := 0; i < tc.registered; i++ {
				taskID := fmt.Sprintf("01REG%021d", i)
				got := byTask[taskID]
				if len(got) != 1 || got[0] != fmt.Sprintf("agent-reg%d", i) {
					t.Errorf("task %s attribution = %v, want [agent-reg%d]", taskID, got, i)
				}
				attributed += len(got)
			}
			if attributed != tc.registered {
				t.Errorf("attributed trees = %d, want %d (no double-count)", attributed, tc.registered)
			}

			// --json: every unregistered basename must appear in the emitted
			// workResult, count must match len(names), and no registered tree name
			// may appear in the names slice.
			jsonOut := captureStdout(t, func() {
				if err := cmdWork(db, []string{"--json"}); err != nil {
					t.Fatalf("cmdWork --json: %v", err)
				}
			})
			var res workResult
			if err := json.Unmarshal([]byte(jsonOut), &res); err != nil {
				t.Fatalf("parse --json output: %v\n%s", err, jsonOut)
			}
			if !reflect.DeepEqual(orphanNames(res.UnregisteredAgentTreeNames), wantUnreg) {
				t.Errorf("--json names = %v, want %v", orphanNames(res.UnregisteredAgentTreeNames), wantUnreg)
			}
			if res.UnregisteredAgentTrees != tc.unregistered {
				t.Errorf("--json count = %d, want %d", res.UnregisteredAgentTrees, tc.unregistered)
			}
			for _, rn := range regNames {
				if strings.Contains(fmt.Sprint(orphanNames(res.UnregisteredAgentTreeNames)), rn) {
					t.Errorf("--json unregistered names %v must not include registered tree %q",
						orphanNames(res.UnregisteredAgentTreeNames), rn)
				}
			}

			// Footer (default view): every unregistered basename must be NAMED, and
			// no registered tree name may appear on the unregistered-tree line.
			footer := captureStdout(t, func() {
				if err := cmdWork(db, nil); err != nil {
					t.Fatalf("cmdWork default: %v", err)
				}
			})
			for _, un := range wantUnreg {
				if !strings.Contains(footer, un) {
					t.Errorf("footer must name unregistered tree %q; got:\n%s", un, footer)
				}
			}
			if tc.unregistered > 0 && !strings.Contains(footer, "unregistered agent-* tree(s) on disk") {
				t.Errorf("footer missing the unregistered-tree line:\n%s", footer)
			}
			for _, rn := range regNames {
				// The registered basename shares the "agent-" prefix but must never be
				// printed on the unregistered-tree footer line.
				for _, line := range splitFooterLines(footer) {
					if strings.Contains(line, "unregistered agent-* tree(s)") && strings.Contains(line, rn) {
						t.Errorf("registered tree %q must not appear on the unregistered footer line: %q", rn, line)
					}
				}
			}
		})
	}
}

// splitFooterLines splits captured stdout into lines for per-line assertions.
func splitFooterLines(s string) []string { return strings.Split(s, "\n") }

// orphanNames projects the orphanTree slice down to its sorted basenames, so the
// name-equality assertions read against the []string expectations regardless of
// the carried mtime/age.
func orphanNames(orphans []orphanTree) []string {
	if orphans == nil {
		return nil
	}
	out := make([]string, len(orphans))
	for i, o := range orphans {
		out[i] = o.Name
	}
	return out
}

// mkOrphanTrees provisions n on-disk .claude/worktrees/agent-* dirs with NO
// registry row and returns their sorted basenames. Hermetic: temp-dir only.
func mkOrphanTrees(t *testing.T, root string, n int) []string {
	t.Helper()
	wtDir := filepath.Join(root, ".claude", "worktrees")
	if err := os.MkdirAll(wtDir, 0o755); err != nil {
		t.Fatalf("mkdir worktrees: %v", err)
	}
	var names []string
	for i := 0; i < n; i++ {
		// zero-padded so lexical sort == numeric sort, making truncation deterministic.
		name := fmt.Sprintf("agent-orphan%03d", i)
		names = append(names, name)
		if err := os.MkdirAll(filepath.Join(wtDir, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	sort.Strings(names)
	return names
}

// TestUnregisteredFooterTruncates pins the bounded footer: with more than
// maxFooterOrphans orphan trees on disk, the human footer lists exactly the
// first maxFooterOrphans basenames plus an "and N more" tail (never the full
// pathological list), while the --json surface still carries EVERY orphan.
func TestUnregisteredFooterTruncates(t *testing.T) {
	const n = maxFooterOrphans + 5 // 13 orphans: comfortably over the cap
	db, root := seedWorkDB(t, nil, nil)
	names := mkOrphanTrees(t, root, n)

	footer := captureStdout(t, func() {
		if err := cmdWork(db, nil); err != nil {
			t.Fatalf("cmdWork default: %v", err)
		}
	})

	// The count and the "and N more" tail must both reflect the full population.
	if !strings.Contains(footer, fmt.Sprintf("%d unregistered agent-* tree(s) on disk", n)) {
		t.Errorf("footer must report the full count %d; got:\n%s", n, footer)
	}
	more := n - maxFooterOrphans
	if !strings.Contains(footer, fmt.Sprintf("and %d more", more)) {
		t.Errorf("footer must collapse the tail into 'and %d more'; got:\n%s", more, footer)
	}
	// Isolate the footer line for exact-membership assertions.
	var line string
	for _, l := range splitFooterLines(footer) {
		if strings.Contains(l, "unregistered agent-* tree(s) on disk") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no unregistered-tree footer line found in:\n%s", footer)
	}
	// The first maxFooterOrphans names appear inline; the rest are collapsed away.
	for _, nm := range names[:maxFooterOrphans] {
		if !strings.Contains(line, nm) {
			t.Errorf("footer line must name the first %d orphans; missing %q: %q", maxFooterOrphans, nm, line)
		}
	}
	for _, nm := range names[maxFooterOrphans:] {
		if strings.Contains(line, nm) {
			t.Errorf("footer line must NOT inline orphan %q past the cap: %q", nm, line)
		}
	}

	// --json still carries the FULL, untruncated set (name-complete).
	jsonOut := captureStdout(t, func() {
		if err := cmdWork(db, []string{"--json"}); err != nil {
			t.Fatalf("cmdWork --json: %v", err)
		}
	})
	var res workResult
	if err := json.Unmarshal([]byte(jsonOut), &res); err != nil {
		t.Fatalf("parse --json: %v\n%s", err, jsonOut)
	}
	if res.UnregisteredAgentTrees != n {
		t.Errorf("--json count = %d, want %d", res.UnregisteredAgentTrees, n)
	}
	if !reflect.DeepEqual(orphanNames(res.UnregisteredAgentTreeNames), names) {
		t.Errorf("--json must carry ALL %d orphan names untruncated; got %v", n, orphanNames(res.UnregisteredAgentTreeNames))
	}
}

// TestUnregisteredCarriesMtimeAge pins the per-orphan mtime/age in --json: a
// synthetic orphan dir stamped to a KNOWN mtime one hour in the past must round
// -trip that mtime (RFC3339, UTC) and report an age of at least ~1h, so an
// operator can judge live-vs-stale from --json alone. Hermetic (temp dir +
// os.Chtimes; no wall-clock flake beyond a generous lower bound).
func TestUnregisteredCarriesMtimeAge(t *testing.T) {
	db, root := seedWorkDB(t, nil, nil)
	wtDir := filepath.Join(root, ".claude", "worktrees")
	if err := os.MkdirAll(filepath.Join(wtDir, "agent-aged"), 0o755); err != nil {
		t.Fatalf("mkdir orphan: %v", err)
	}
	// Stamp a known mtime: exactly one hour ago, truncated to whole seconds so
	// the RFC3339 round-trip is exact.
	known := time.Now().Add(-time.Hour).Truncate(time.Second).UTC()
	if err := os.Chtimes(filepath.Join(wtDir, "agent-aged"), known, known); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	_, unregistered := agentWorktreesByTask(db)
	if len(unregistered) != 1 {
		t.Fatalf("want exactly 1 orphan, got %d: %+v", len(unregistered), unregistered)
	}
	o := unregistered[0]
	if o.Name != "agent-aged" {
		t.Errorf("orphan name = %q, want agent-aged", o.Name)
	}
	if o.Mtime != known.Format(time.RFC3339) {
		t.Errorf("orphan mtime = %q, want %q", o.Mtime, known.Format(time.RFC3339))
	}
	// Age is measured at scan time (>= known age; allow the test's own runtime as
	// upper slack). Lower bound: at least the hour we backdated, minus a second.
	if o.AgeSecs < 3599 {
		t.Errorf("orphan age_secs = %d, want >= ~3600 (backdated 1h)", o.AgeSecs)
	}
	if o.AgeSecs > 3600+3600 {
		t.Errorf("orphan age_secs = %d implausibly large for a just-created backdated dir", o.AgeSecs)
	}

	// The same mtime/age must survive the --json marshal round-trip.
	jsonOut := captureStdout(t, func() {
		if err := cmdWork(db, []string{"--json"}); err != nil {
			t.Fatalf("cmdWork --json: %v", err)
		}
	})
	var res workResult
	if err := json.Unmarshal([]byte(jsonOut), &res); err != nil {
		t.Fatalf("parse --json: %v\n%s", err, jsonOut)
	}
	if len(res.UnregisteredAgentTreeNames) != 1 {
		t.Fatalf("--json want 1 orphan, got %+v", res.UnregisteredAgentTreeNames)
	}
	jo := res.UnregisteredAgentTreeNames[0]
	if jo.Name != "agent-aged" || jo.Mtime != known.Format(time.RFC3339) || jo.AgeSecs < 3599 {
		t.Errorf("--json orphan = %+v, want name=agent-aged mtime=%s age>=~3600", jo, known.Format(time.RFC3339))
	}
}

// TestWorkBucketsExampleMatchesDefaults proves the checked-in
// work-buckets.json.example parses to the SAME rule table (count, order,
// bucket, scope, patterns) as the built-in defaultBucketRules, so the shipped
// example is a faithful, copy-pasteable starting point rather than drift. The
// `_README` key must be ignored by the loader (encoding/json drops unknown
// fields).
func TestWorkBucketsExampleMatchesDefaults(t *testing.T) {
	b, err := os.ReadFile("work-buckets.json.example")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	var got []bucketRule
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("example does not parse as []bucketRule: %v", err)
	}
	if len(got) != len(defaultBucketRules) {
		t.Fatalf("example rule count = %d, want %d", len(got), len(defaultBucketRules))
	}
	for i := range defaultBucketRules {
		want := defaultBucketRules[i]
		if got[i].Bucket != want.Bucket {
			t.Errorf("rule %d bucket = %q, want %q", i, got[i].Bucket, want.Bucket)
		}
		if got[i].Scope != want.Scope {
			t.Errorf("rule %d (%s) scope = %q, want %q", i, want.Bucket, got[i].Scope, want.Scope)
		}
		if !reflect.DeepEqual(got[i].Patterns, want.Patterns) {
			t.Errorf("rule %d (%s) patterns = %v, want %v", i, want.Bucket, got[i].Patterns, want.Patterns)
		}
	}
}

// TestLoaderIgnoresExampleSuffix proves loadBucketRules auto-loads only the
// no-suffix work-buckets.json and never the *.example: a fixture repo holding
// ONLY a (deliberately malformed) work-buckets.json.example must still resolve
// to the built-in defaults without error.
func TestLoaderIgnoresExampleSuffix(t *testing.T) {
	_, root := seedWorkDB(t, nil, nil)
	cfgDir := filepath.Join(root, "scripts", "taskdb")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir cfg: %v", err)
	}
	// Malformed on purpose: if the loader ever picked up the .example suffix this
	// would surface as a parse error instead of clean defaults.
	if err := os.WriteFile(filepath.Join(cfgDir, "work-buckets.json.example"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write example: %v", err)
	}
	rules, err := loadBucketRules()
	if err != nil {
		t.Fatalf("loadBucketRules must ignore the .example suffix and default cleanly, got: %v", err)
	}
	if len(rules) != len(defaultBucketRules) {
		t.Errorf("with only a .example present, loader must use defaults (%d rules), got %d", len(defaultBucketRules), len(rules))
	}
}
