// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// hooksPathValue is the tracked hooks dir git is pointed at. Keep in sync with
// the Makefile's HOOKS_PATH and scripts/hooks/.
const hooksPathValue = "scripts/hooks"

// cmdSetup is the explicit, one-shot repo bootstrap: point git at the tracked
// hooks dir (idempotent, conflict-safe) and report whether .bin/taskdb is stale.
// It needs no database, so it works on a fresh clone before any thaw — main
// routes it before openDB. setup-repo.sh and the auto-nudge share installHooks.
func cmdSetup(args []string) error {
	if err := rejectUnknownFlags(args, "taskdb setup"); err != nil {
		return err
	}
	root, err := repoRoot()
	if err != nil {
		return err
	}
	switch st := installHooks(root); st.kind {
	case hookInstalled:
		fmt.Printf("taskdb setup: installed git hooks — core.hooksPath=%s\n", hooksPathValue)
		fmt.Println("  freeze runs pre-commit (DB → tasks/*.json, staged); thaw runs post-checkout/merge/rewrite.")
	case hookAlreadyOurs:
		fmt.Printf("taskdb setup: git hooks already active (core.hooksPath=%s)\n", hooksPathValue)
	case hookConflict:
		fmt.Printf("taskdb setup: ⚠ core.hooksPath is %q, not %q — leaving it untouched.\n", st.current, hooksPathValue)
		fmt.Println("  taskdb freeze/thaw hooks are INACTIVE. Either chain our hooks from your")
		fmt.Printf("  hooks dir, or take ours over with:  git config core.hooksPath %s\n", hooksPathValue)
	case hookUndetermined:
		fmt.Printf("taskdb setup: ⚠ could not determine whether core.hooksPath %q is this repo's own default (a transient `git rev-parse` failure) — left untouched.\n", st.current)
		fmt.Println("  Re-run `taskdb setup` (usually clears), or take ours over explicitly with:")
		fmt.Printf("  git config core.hooksPath %s\n", hooksPathValue)
	case hookError:
		return st.err
	}
	if err := registerMergeDriver(root); err != nil {
		fmt.Printf("taskdb setup: ⚠ could not register the tasks/*.json merge driver: %v\n", err)
		fmt.Println("  (cross-coordinator task merges will fall back to plain text conflicts.)")
	} else {
		fmt.Println("  registered merge.taskdb driver for tasks/*.json (ID-stable 3-way union; re-run setup on EVERY machine).")
	}
	if ensureMaintenanceConfig(root) {
		fmt.Println("  set maintenance.auto=false + gc.auto=0 (disables git's background maintenance scheduler — the packed-refs.lock racer under concurrent worktrees; docs/24 §2).")
	} else {
		fmt.Println("  maintenance.auto=false + gc.auto=0 already set (concurrent-worktree contention fix; docs/24 §2).")
	}
	if w := binaryStaleWarning(root); w != "" {
		fmt.Println(w)
	}
	return nil
}

// mergeDriverName / mergeDriverValue are the git config values that wire the
// tasks/*.json merge driver. Kept as constants so registerMergeDriver (explicit
// setup) and ensureMergeDriver (the every-invocation self-heal) agree on the
// exact strings — a drift between them would make the nudge re-register on every
// command or never recognize an already-correct driver.
const (
	mergeDriverName  = "taskdb ID-stable 3-way task/note JSON merge"
	mergeDriverValue = ".bin/taskdb merge-json %O %A %B %P"
)

// registerMergeDriver wires the tasks/*.json git merge driver. .gitattributes
// routes tasks/{task,note}-*.json to merge=taskdb; this points that driver at
// `.bin/taskdb merge-json`. git NEVER auto-applies a merge driver from a clone
// (same trust reason as core.hooksPath), so every clone — on every machine —
// must have `taskdb setup` (or the every-invocation self-heal in repoNudge) run
// for concurrent task edits to RECONCILE by id instead of clobber. Idempotent:
// git config overwrites the keys. If .bin/taskdb is absent at merge time the
// driver simply fails and git falls back to text conflict markers (safe).
func registerMergeDriver(root string) error {
	if err := exec.Command("git", "-C", root, "config", "merge.taskdb.name", mergeDriverName).Run(); err != nil {
		return fmt.Errorf("set merge.taskdb.name: %w", err)
	}
	if err := exec.Command("git", "-C", root, "config", "merge.taskdb.driver", mergeDriverValue).Run(); err != nil {
		return fmt.Errorf("set merge.taskdb.driver: %w", err)
	}
	return nil
}

// mergeKind classifies the outcome of ensureMergeDriver.
type mergeKind int

const (
	mergeAlreadyOurs mergeKind = iota // merge.taskdb.driver already == mergeDriverValue
	mergeInstalled                    // was unset; we registered it
	mergeConflict                     // set to a different value; left untouched
	mergeErr                          // git invocation failed (silent; non-fatal)
)

// ensureMergeDriver is the every-invocation analog of installHooks for the
// tasks/*.json merge driver: it closes the clone-skipped-setup gap where hooks
// self-heal but the merge driver did not, so a clone (or `git clone --local`
// worktree) that never ran `taskdb setup` silently fell back to line-based
// conflict markers on concurrent task edits. Like installHooks it only WRITES in
// the unset case and never clobbers an operator-chosen value (the key is
// taskdb-owned, but a deliberate override is still respected).
func ensureMergeDriver(root string) (mergeKind, string) {
	cur, set, err := gitConfigGet(root, "merge.taskdb.driver")
	if err != nil {
		return mergeErr, ""
	}
	switch {
	case set && cur == mergeDriverValue:
		return mergeAlreadyOurs, ""
	case set && cur != "":
		return mergeConflict, cur
	default: // unset or empty
		if err := registerMergeDriver(root); err != nil {
			return mergeErr, ""
		}
		return mergeInstalled, ""
	}
}

// ensureMaintenanceConfig seeds maintenance.auto=false + gc.auto=0 on the shared
// $GIT_DIR — the every-invocation analog of installHooks for the linked-worktree
// contention fix (docs/24 §2, resolving docs/23 OQ1). git 2.54's background
// maintenance scheduler (spawned `--detach` by commit/fetch) rewrites the shared
// packed-refs while sibling linked worktrees do concurrent ref churn; the loser
// of the compare-and-swap gets `cannot lock ref`. Turning the scheduler off
// drops unrecovered ref-lock failures from up-to-94 to 0 at 32-way concurrency
// (and runs 2-6x faster). gc.auto=0 is belt-and-suspenders: the git 2.54 trigger
// is the maintenance scheduler, NOT legacy `gc --auto`, so gc.auto alone does not
// fix it — but pinning both documents intent and covers older gits. (Run an
// out-of-band scheduled gc/repack to keep the object store healthy with
// auto-maintenance off.) Only writes when a key is not already off, so the
// steady state is silent; never errors fatally. Returns true if it wrote.
func ensureMaintenanceConfig(root string) (changed bool) {
	// maintenance.auto is a bool; gc.auto is an int threshold (0 disables).
	cur, set, err := gitConfigGet(root, "maintenance.auto")
	if err == nil && !(set && gitIsFalse(cur)) {
		if exec.Command("git", "-C", root, "config", "maintenance.auto", "false").Run() == nil {
			changed = true
		}
	}
	cur, set, err = gitConfigGet(root, "gc.auto")
	if err == nil && !(set && strings.TrimSpace(cur) == "0") {
		if exec.Command("git", "-C", root, "config", "gc.auto", "0").Run() == nil {
			changed = true
		}
	}
	return changed
}

// gitIsFalse reports whether a git config string is a falsey/disabled value, so
// re-running ensureMaintenanceConfig over a hand-set "off"/"0"/"no" is a no-op
// rather than a churning rewrite to the canonical "false".
func gitIsFalse(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "false", "0", "no", "off", "":
		return true
	}
	return false
}

// hookKind classifies the outcome of installHooks.
type hookKind int

const (
	hookInstalled    hookKind = iota // core.hooksPath was unset; we set it
	hookAlreadyOurs                  // already == hooksPathValue; nothing to do
	hookConflict                     // set to a DETERMINED different path; left untouched
	hookUndetermined                 // set to a non-ours path we couldn't classify (transient git failure); left untouched, reported softly
	hookError                        // git invocation failed
)

type hookStatus struct {
	kind    hookKind
	current string // the conflicting value, for hookConflict
	err     error  // for hookError
}

// installHooks makes git use the tracked hooks, without ever clobbering a
// hooksPath the operator chose themselves:
//   - unset                 → set core.hooksPath=scripts/hooks (fresh-clone case)
//   - == scripts/hooks      → no-op (already ours)
//   - == repo default hooks → set core.hooksPath=scripts/hooks (see below)
//   - anything else         → report a conflict; leave it alone (bail + warn)
//
// The repo-default case is treated like unset on purpose: a core.hooksPath
// explicitly pinned to this repo's own $GIT_DIR/hooks is NOT a deliberate
// override — that dir holds only inert *.sample files git never runs, so it is
// functionally identical to unset, yet it silently disables freeze/thaw. Some
// tools (and operators) write the default path in; without this carve-out
// `taskdb setup` would mis-classify it as a conflict and refuse to repair it,
// leaving the DB↔JSON automation off and inviting stale-clone freeze clobbers.
//
// It also re-asserts the +x bit on the hook files (a fresh checkout usually
// preserves it, but a copy/extract may not). Best-effort and side-effect-light:
// the only mutation is a single `git config` write in the install case.
func installHooks(root string) hookStatus {
	cur, set, err := gitConfigGet(root, "core.hooksPath")
	if err != nil {
		return hookStatus{kind: hookError, err: err}
	}
	// Already ours — the steady state. Keep this FIRST so the per-invocation
	// nudge never shells out to `git rev-parse` on the hot path.
	if set && cur == hooksPathValue {
		ensureHookBits(root)
		return hookStatus{kind: hookAlreadyOurs}
	}
	// Set to some OTHER path: classify it. The repo's own default hooks dir is
	// treated like unset (repaired below); a deliberate operator override is a
	// conflict we leave alone. But a transient `git rev-parse` failure (common
	// under this box's concurrent git load) must NOT be mistaken for a deliberate
	// override: that downgraded a repo-default into a hookConflict and emitted a
	// false "freeze/thaw INACTIVE" banner that self-cleared on the next
	// invocation (observed 2026-06-14). So distinguish "determined custom" from
	// "couldn't tell" and, when uncertain, neither repair nor cry conflict.
	if set && cur != "" {
		isDefault, determined := hooksPathIsRepoDefault(root, cur)
		if !determined {
			return hookStatus{kind: hookUndetermined, current: cur}
		}
		if !isDefault {
			return hookStatus{kind: hookConflict, current: cur}
		}
		// repo default → fall through to install ours.
	}
	// unset, empty, or pinned to the repo's own default hooks dir → install ours.
	if err := exec.Command("git", "-C", root, "config", "core.hooksPath", hooksPathValue).Run(); err != nil {
		return hookStatus{kind: hookError, err: fmt.Errorf("set core.hooksPath: %w", err)}
	}
	ensureHookBits(root)
	return hookStatus{kind: hookInstalled}
}

// hooksPathIsRepoDefault reports whether the configured core.hooksPath points at
// this repo's own default git hooks dir ($GIT_COMMON_DIR/hooks) — i.e. an
// explicit set to the value git would use anyway. installHooks treats that like
// the unset case (see its doc comment).
//
// The default dir is resolved via `git rev-parse --git-common-dir` (NOT
// `--git-path hooks`, which is circular — it just echoes core.hooksPath when the
// key is set). A relative core.hooksPath is resolved against the working-tree
// root, matching git's own interpretation. Identity is decided by os.SameFile
// (robust to symlinks, "..", and trailing slashes), falling back to cleaned-path
// equality only when a dir can't be stat'd.
// The second return, `determined`, is false ONLY when the repo's git-common-dir
// could not be resolved (a transient `git rev-parse` failure that survived the
// retries in gitCommonDir). Callers MUST treat undetermined as "couldn't tell",
// never as a definitive custom override — the old code returned a bare `false`
// here, which let a transient failure masquerade as a deliberate hooksPath and
// raise a false "freeze/thaw INACTIVE" conflict banner.
func hooksPathIsRepoDefault(root, cur string) (isDefault, determined bool) {
	if cur == "" {
		return false, true
	}
	abs := cur
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, cur)
	}
	common, ok := gitCommonDir(root)
	if !ok {
		return false, false
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(root, common)
	}
	def := filepath.Join(common, "hooks")
	if fi1, e1 := os.Stat(abs); e1 == nil {
		if fi2, e2 := os.Stat(def); e2 == nil {
			return os.SameFile(fi1, fi2), true
		}
	}
	return filepath.Clean(abs) == filepath.Clean(def), true
}

// gitCommonDir returns `git rev-parse --git-common-dir` for root, retrying a few
// times to ride out a transient failure under concurrent git activity (a sibling
// worktree op, an interrupted index). The backoff is paid ONLY on the error path
// — a normal repo answers on the first call, so the hot-path nudge adds nothing.
// ok=false only when rev-parse persistently fails (a genuinely broken repo).
func gitCommonDir(root string) (string, bool) {
	for _, delay := range []time.Duration{0, 20 * time.Millisecond, 60 * time.Millisecond} {
		if delay > 0 {
			time.Sleep(delay)
		}
		out, err := exec.Command("git", "-C", root, "rev-parse", "--git-common-dir").Output()
		if err == nil {
			return strings.TrimSpace(string(out)), true
		}
	}
	return "", false
}

// gitConfigGet reads a local git config key. A clean exit-1 from `git config`
// means the key is unset (set=false, no error); any other failure is real.
func gitConfigGet(root, key string) (val string, set bool, err error) {
	out, err := exec.Command("git", "-C", root, "config", "--get", key).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(string(out)), true, nil
}

// ensureHookBits sets the executable bit on every file in scripts/hooks/.
func ensureHookBits(root string) {
	dir := filepath.Join(root, hooksPathValue)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if fi, err := os.Stat(p); err == nil && fi.Mode()&0o111 == 0 {
			_ = os.Chmod(p, fi.Mode()|0o111)
		}
	}
}

// binaryStaleWarning returns a non-empty warning when .bin/taskdb is older than
// the newest taskdb source file — i.e. the binary the git hooks and parallel
// sessions invoke predates a source change and should be rebuilt with
// `make taskdb`. Returns "" when the binary is absent (the hooks no-op, so
// there's nothing to be stale against), up to date, or the tree is unreadable.
func binaryStaleWarning(root string) string {
	bin := filepath.Join(root, ".bin", "taskdb")
	bfi, err := os.Stat(bin)
	if err != nil {
		return ""
	}
	srcDir := filepath.Join(root, "scripts", "taskdb")
	var newest time.Time
	var newestFile string
	_ = filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") && name != "go.mod" && name != "go.sum" {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
			newestFile = name
		}
		return nil
	})
	if newestFile != "" && newest.After(bfi.ModTime()) {
		return fmt.Sprintf("taskdb: ⚠ .bin/taskdb is STALE — %s is newer than the binary; rebuild: make taskdb", newestFile)
	}
	return ""
}

// repoNudge is best-effort repo-health maintenance run on every CLI invocation
// (see main). In the steady state it is SILENT — it speaks only when something
// needs attention: a fresh clone with no hooks (auto-installs + says so), a
// conflicting hooksPath (warns, never clobbers), or a stale .bin/taskdb (warns
// to rebuild). All output is stderr; nothing here can fail the command.
func repoNudge() {
	root, err := repoRoot()
	if err != nil {
		return
	}
	switch st := installHooks(root); st.kind {
	case hookInstalled:
		fmt.Fprintf(os.Stderr, "taskdb: installed git hooks (core.hooksPath=%s) — task freeze/thaw now run on commit\n", hooksPathValue)
	case hookConflict:
		fmt.Fprintf(os.Stderr, "taskdb: ⚠ core.hooksPath=%q, not %q — task freeze/thaw hooks INACTIVE; run `taskdb setup` for the fix\n", st.current, hooksPathValue)
	case hookUndetermined:
		// Couldn't classify a non-ours core.hooksPath (a transient `git rev-parse`
		// failure under concurrent git load). Stay SILENT on the hot path: it
		// self-clears on the next invocation, and we must not raise the INACTIVE
		// banner on what may well BE the repo default. `taskdb setup` reports it.
	}
	switch k, cur := ensureMergeDriver(root); k {
	case mergeInstalled:
		fmt.Fprintln(os.Stderr, "taskdb: registered tasks/*.json merge driver (merge.taskdb) — concurrent task edits now reconcile by id instead of conflicting")
	case mergeConflict:
		fmt.Fprintf(os.Stderr, "taskdb: ⚠ merge.taskdb.driver=%q, not the taskdb driver — concurrent task JSON edits may hit text conflicts; run `taskdb setup` to fix\n", cur)
	}
	if ensureMaintenanceConfig(root) {
		fmt.Fprintln(os.Stderr, "taskdb: set maintenance.auto=false + gc.auto=0 on the shared .git — disables the background maintenance scheduler that races packed-refs.lock under concurrent worktrees (docs/24 §2)")
	}
	if w := binaryStaleWarning(root); w != "" {
		fmt.Fprintln(os.Stderr, w)
	}
}
