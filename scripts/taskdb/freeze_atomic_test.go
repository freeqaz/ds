// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// writeJSON is write-temp-then-rename so a concurrent reader (a parallel
// coordinator's freeze, the pre-commit `git add tasks/`, a `git status`) never
// observes a half-written task-/note-*.json. These pin that contract:
//
//   - TestWriteJSONAtomicNoLeak: the output is correct, leaves no .tmp-* file
//     behind, and a leaked temp would not match the task-*/note-* globs the
//     freeze --gc keepset and the thaw drop-guard scan.
//   - TestWriteJSONConcurrentReaderNeverPartial: hammering one path from many
//     writers while a reader re-reads it, every observed read is either absent
//     or a complete, parseable document — never a truncation.

func TestWriteJSONAtomicNoLeak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "task-01TEST.json")
	task := &Task{ID: "01TEST", Title: "atomic", Status: StatusOpen, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}

	if err := writeJSON(path, task); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}

	// Output matches the canonical MarshalIndent + trailing newline.
	want, _ := json.MarshalIndent(task, "", "  ")
	want = append(want, '\n')
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("content mismatch:\n got: %q\nwant: %q", got, want)
	}

	// No temp file leaked, and any temp that *did* leak would be invisible to
	// the task-*/note-* globs (so it can never be staged or trip the drop-guard).
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "task-01TEST.json" {
			t.Fatalf("unexpected file left in dir: %q", e.Name())
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "task-*.json")); len(m) != 1 {
		t.Fatalf("task-*.json glob = %v, want exactly the real file", m)
	}
}

func TestWriteJSONConcurrentReaderNeverPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "task-01RACE.json")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reader: until told to stop, every read must be absent or fully parseable.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if err != nil { // not yet created; fine
				continue
			}
			var tk Task
			if err := json.Unmarshal(b, &tk); err != nil {
				t.Errorf("reader saw a partial/corrupt file (%d bytes): %v", len(b), err)
				return
			}
		}
	}()

	// Writers: many overlapping freezes of the same id.
	for i := 0; i < 50; i++ {
		task := &Task{ID: "01RACE", Title: "race", Status: StatusOpen, Priority: i % 4, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		if err := writeJSON(path, task); err != nil {
			t.Fatalf("writeJSON #%d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	if m, _ := filepath.Glob(filepath.Join(dir, ".tmp-*")); len(m) != 0 {
		t.Fatalf("temp files leaked after concurrent writes: %v", m)
	}
}
