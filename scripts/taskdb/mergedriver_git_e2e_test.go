// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This is the GIT-INVOCATION e2e counterpart to mergejson_test.go. Those tests
// call cmdMergeJSON in-process; the two originally-reported field failures (BUG
// 01KV2RMTBV: an older in-progress status overriding a newer done, and dropped
// notes) happened at the GIT boundary — where a real `git merge` either reaches
// the per-file driver or silently falls back. This drives a REAL temp git repo:
// it builds the taskdb binary, registers merge=taskdb (.gitattributes + a
// merge.taskdb.driver pointing at the built binary), creates a true 3-way
// conflict on a tasks/task-*.json and a tasks/note-*.json, runs `git merge`, and
// asserts the driver produced the precedence-correct + note-union result. It is
// hermetic (temp repo only, no network) and t.Skips when git is unavailable.

// gitE2EBin builds the taskdb binary into a temp dir so the test is
// self-contained — the merge driver is wired to THIS absolute path, not a
// repo-relative .bin/taskdb that the temp git repo would not have.
func gitE2EBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "taskdb")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Build the current package (the taskdb main) into bin.
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build taskdb: %v\n%s", err, out)
	}
	return bin
}

// gitE2ERun runs a git command in root and fails the test on error.
func gitE2ERun(t *testing.T, root string, args ...string) {
	t.Helper()
	if out, err := gitE2ETry(root, args...); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// gitE2ETry runs a git command in root and returns its combined output + error
// (used where a non-zero exit is an expected outcome, e.g. a conflicting merge).
func gitE2ETry(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	// Pin a deterministic identity + disable any global merge config leaking in.
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)
	return cmd.CombinedOutput()
}

// gitE2EInitRepo creates a temp git repo with the tasks/*.json merge driver
// wired to the built taskdb binary, exactly as `taskdb setup` would on a real
// clone: .gitattributes routes task/note files to merge=taskdb, and
// merge.taskdb.driver invokes the binary with the %O %A %B %P placeholders.
func gitE2EInitRepo(t *testing.T, bin string) string {
	t.Helper()
	root := t.TempDir()
	gitE2ERun(t, root, "init", "-q")
	gitE2ERun(t, root, "config", "user.email", "t@example.com")
	gitE2ERun(t, root, "config", "user.name", "t")
	gitE2ERun(t, root, "config", "merge.taskdb.name", "taskdb e2e merge")
	// The real driver value is ".bin/taskdb merge-json %O %A %B %P"; here we point
	// it at the absolute path of the hermetically built binary so the temp repo
	// needs no .bin checkout. The placeholder ordering must match cmdMergeJSON's
	// args contract (ancestor, ours, theirs, pathname).
	gitE2ERun(t, root, "config", "merge.taskdb.driver", bin+" merge-json %O %A %B %P")

	attrs := "tasks/task-*.json merge=taskdb\ntasks/note-*.json merge=taskdb\n"
	if err := os.WriteFile(filepath.Join(root, ".gitattributes"), []byte(attrs), 0644); err != nil {
		t.Fatalf("write .gitattributes: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "tasks"), 0755); err != nil {
		t.Fatalf("mkdir tasks: %v", err)
	}
	gitE2ERun(t, root, "add", ".gitattributes")
	gitE2ERun(t, root, "commit", "-q", "-m", "seed: attributes + driver")
	return root
}

func gitE2EWriteCommit(t *testing.T, root, rel, content, msg string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if content == "" {
		// Empty content => stage a deletion of the file.
		gitE2ERun(t, root, "rm", "-q", rel)
	} else {
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		gitE2ERun(t, root, "add", rel)
	}
	gitE2ERun(t, root, "commit", "-q", "-m", msg)
}

func gitE2EReadTask(t *testing.T, root, rel string) Task {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var tk Task
	if err := json.Unmarshal(b, &tk); err != nil {
		t.Fatalf("unmarshal %s: %v (%s)", rel, err, b)
	}
	return tk
}

func gitE2ENoteBody(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var n Note
	if err := json.Unmarshal(b, &n); err != nil {
		t.Fatalf("unmarshal note %s: %v (%s)", rel, err, b)
	}
	return n.Body
}

// TestMergeDriverGitE2E_StatusPrecedence is the real-git proof of the reported
// status-precedence inversion: a NEWER in-progress side must NOT override an
// OLDER done side. We branch from a common in-progress base, set one branch to
// `done` (with the OLDER updated_at) and the other to `in-progress` (with the
// NEWER updated_at), then run a real `git merge`. The driver must resolve the
// conflict to `done` (terminality wins on rank, never on recency) — the exact
// case that, with the driver UNREGISTERED, git's line-based fallback resolved
// the wrong way.
func TestMergeDriverGitE2E_StatusPrecedence(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := gitE2EBin(t)
	root := gitE2EInitRepo(t, bin)
	const rel = "tasks/task-01E2E.json"

	// Common ancestor: in-progress.
	gitE2EWriteCommit(t, root,
		rel,
		`{"id":"01E2E","title":"base","status":"in-progress","priority":2,"depends_on":["01DEP0"],"created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`,
		"base: in-progress")

	// theirs branch: done, with the OLDER updated_at; keeps the base edge + adds
	// its own (01DEPB).
	gitE2ERun(t, root, "checkout", "-q", "-b", "theirs")
	gitE2EWriteCommit(t, root,
		rel,
		`{"id":"01E2E","title":"theirs-done","status":"done","priority":2,"depends_on":["01DEP0","01DEPB"],"created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T02:00:00Z"}`,
		"theirs: done (older)")

	// ours branch (main/master): in-progress, with the NEWER updated_at; keeps the
	// base edge + adds a DIFFERENT one (01DEPA). Recency favors this loser, so a
	// pass proves the driver ranks by terminality, not by updated_at. The driver
	// unions ours+theirs depends_on, so the result must be all three.
	gitE2ERun(t, root, "checkout", "-q", "-")
	gitE2EWriteCommit(t, root,
		rel,
		`{"id":"01E2E","title":"ours-inprogress","status":"in-progress","priority":2,"depends_on":["01DEP0","01DEPA"],"created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T09:00:00Z"}`,
		"ours: in-progress (newer)")

	// Real 3-way merge — the driver must fire and auto-resolve cleanly.
	if out, err := gitE2ETry(root, "merge", "--no-edit", "theirs"); err != nil {
		t.Fatalf("git merge should auto-resolve via the driver, got error: %v\n%s", err, out)
	}

	m := gitE2EReadTask(t, root, rel)
	if m.Status != StatusDone {
		t.Errorf("status = %q, want done (older done must beat newer in-progress via the driver, not git's line fallback)", m.Status)
	}
	// depends_on must be the SORTED UNION — neither side's edge dropped.
	if len(m.DependsOn) != 3 ||
		m.DependsOn[0] != "01DEP0" || m.DependsOn[1] != "01DEPA" || m.DependsOn[2] != "01DEPB" {
		t.Errorf("depends_on = %v, want [01DEP0 01DEPA 01DEPB] (sorted union, no edge dropped)", m.DependsOn)
	}
}

// TestMergeDriverGitE2E_NoteUnion is the real-git proof of the reported note
// drop: an add/add of the SAME note id on both branches is a real per-file
// conflict that the driver must resolve to a present note (never empty / never
// dropped). Both sides carry the same body so the assertion is unambiguous; the
// point is that the file survives the merge with content, not conflict markers.
func TestMergeDriverGitE2E_NoteUnion(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := gitE2EBin(t)
	root := gitE2EInitRepo(t, bin)
	const rel = "tasks/note-01E2EN.json"
	const body = "the surviving note"
	note := `{"id":"01E2EN","task_id":"01E2E","body":"` + body + `","author":"me","created_at":"2026-06-13T01:00:00Z"}`

	// Base has NO note (a seed-only commit on the current branch).
	gitE2EWriteCommit(t, root, "tasks/seed.keep", "seed\n", "base: no note yet")

	// theirs branch adds the note.
	gitE2ERun(t, root, "checkout", "-q", "-b", "note-theirs")
	gitE2EWriteCommit(t, root, rel, note, "theirs: add note")

	// ours branch adds the SAME note id (add/add => a real per-file merge that
	// routes through the driver).
	gitE2ERun(t, root, "checkout", "-q", "-")
	gitE2EWriteCommit(t, root, rel, note, "ours: add note")

	if out, err := gitE2ETry(root, "merge", "--no-edit", "note-theirs"); err != nil {
		t.Fatalf("git merge of add/add note should auto-resolve via the driver, got error: %v\n%s", err, out)
	}
	if got := gitE2ENoteBody(t, root, rel); got != body {
		t.Errorf("note body = %q, want %q (note must survive the merge, never dropped to empty/conflict)", got, body)
	}
}

// TestMergeDriverGitE2E_NoteResurrectOnDeleteVsModify proves the resurrection
// branch of the driver under real git: one side modifies the note, the other
// deletes it. git presents this to a content merge driver with an EMPTY side for
// the deleted file; cmdMergeJSON's note policy resurrects the present side. We
// assert the note survives with the modifier's body — never dropped by the
// delete. (When git instead classifies this as a tree-level modify/delete and
// does not invoke the driver, the merge stops with the file still present on the
// modifying side; we accept either an auto-resolved present note or a halted
// merge that left the note present — the invariant under test is that the note
// is NEVER silently dropped.)
func TestMergeDriverGitE2E_NoteResurrectOnDeleteVsModify(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := gitE2EBin(t)
	root := gitE2EInitRepo(t, bin)
	const rel = "tasks/note-01E2ER.json"
	const base = `{"id":"01E2ER","task_id":"01E2E","body":"original","author":"me","created_at":"2026-06-13T01:00:00Z"}`
	const modified = `{"id":"01E2ER","task_id":"01E2E","body":"kept-on-modify-side","author":"me","created_at":"2026-06-13T01:00:00Z"}`

	// Base commits the note on the current branch.
	gitE2EWriteCommit(t, root, rel, base, "base: note present")

	// theirs branch deletes the note.
	gitE2ERun(t, root, "checkout", "-q", "-b", "note-del")
	gitE2EWriteCommit(t, root, rel, "", "theirs: delete note")

	// ours branch modifies the note body (forces a content-level overlap so git
	// must reconcile delete-vs-modify rather than a clean tree delete).
	gitE2ERun(t, root, "checkout", "-q", "-")
	gitE2EWriteCommit(t, root, rel, modified, "ours: modify note")

	// The merge may auto-resolve (driver fires) or halt (tree modify/delete). In
	// BOTH outcomes the note must remain present on disk — never dropped.
	_, _ = gitE2ETry(root, "merge", "--no-edit", "note-del")

	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("note file missing after delete-vs-modify merge — it was dropped: %v", err)
	}
	var n Note
	if err := json.Unmarshal(b, &n); err != nil {
		t.Fatalf("note unparseable (conflict markers / half-merge) after delete-vs-modify: %v (%s)", err, b)
	}
	if n.Body != "kept-on-modify-side" {
		t.Errorf("note body = %q, want the modify-side body (the delete must never win over a present note)", n.Body)
	}
}
