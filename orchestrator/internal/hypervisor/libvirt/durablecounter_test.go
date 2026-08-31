// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDurableCounterMonotonicAndPersists: Next() hands 0,1,2,… and the on-disk
// next-index advances ahead of each handed index (crash-safe before return).
func TestDurableCounterMonotonicAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idx.counter")
	c, err := NewDurableCounter(path)
	if err != nil {
		t.Fatalf("NewDurableCounter: %v", err)
	}
	for want := uint64(0); want < 5; want++ {
		got, err := c.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if got != want {
			t.Fatalf("Next = %d, want %d", got, want)
		}
		// The persisted next-index is strictly past the just-handed index.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read counter file: %v", err)
		}
		if string(data) != itoa(want+1) {
			t.Fatalf("persisted next = %q, want %q (past handed index %d)", data, itoa(want+1), got)
		}
	}
}

// TestDurableCounterSurvivesRestart: a fresh NewDurableCounter on the SAME path
// RESUMES past every index already handed — never re-hands a live index (D66).
func TestDurableCounterSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idx.counter")
	c1, err := NewDurableCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := c1.Next(); err != nil {
			t.Fatalf("Next: %v", err)
		}
	}
	// "Restart": a fresh counter over the same persisted file.
	c2, err := NewDurableCounter(path)
	if err != nil {
		t.Fatalf("NewDurableCounter (restart): %v", err)
	}
	got, err := c2.Next()
	if err != nil {
		t.Fatalf("Next after restart: %v", err)
	}
	if got != 8 {
		t.Fatalf("post-restart Next = %d, want 8 (never re-hand 0..7)", got)
	}
}

// TestDurableCounterSeedAtLeastForwardOnly: SeedAtLeast advances the next index
// past `highest` (the next Next() is strictly greater); a `highest` below the
// current position is a no-op (never moves backward, D66).
func TestDurableCounterSeedAtLeastForwardOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idx.counter")
	c, err := NewDurableCounter(path)
	if err != nil {
		t.Fatal(err)
	}
	// Seed past the highest recovered index 7 → next Next() yields 8.
	c.SeedAtLeast(7)
	got, err := c.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if got != 8 {
		t.Fatalf("Next after SeedAtLeast(7) = %d, want 8 (strictly past 7)", got)
	}
	// A backward seed is a no-op: next is now 9, SeedAtLeast(3) must not rewind it.
	c.SeedAtLeast(3)
	got, err = c.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if got != 9 {
		t.Fatalf("Next after backward SeedAtLeast(3) = %d, want 9 (forward-only, no rewind)", got)
	}
	// SeedAtLeast persists the high-water mark even before a draw.
	path2 := filepath.Join(t.TempDir(), "idx2.counter")
	c2, _ := NewDurableCounter(path2)
	c2.SeedAtLeast(42)
	data, err := os.ReadFile(path2)
	if err != nil {
		t.Fatalf("read seeded counter file: %v", err)
	}
	if string(data) != itoa(43) {
		t.Fatalf("seeded persisted next = %q, want %q", data, itoa(43))
	}
}

// TestDurableCounterRejectsCorruptAndEmptyPath: a present-but-unparseable counter
// file is a hard error (never silently reset to 0); an empty path is rejected.
func TestDurableCounterRejectsCorruptAndEmptyPath(t *testing.T) {
	if _, err := NewDurableCounter(""); err == nil {
		t.Fatal("expected NewDurableCounter to reject an empty path")
	}
	path := filepath.Join(t.TempDir(), "idx.counter")
	if err := os.WriteFile(path, []byte("not-a-number"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDurableCounter(path); err == nil {
		t.Fatal("expected NewDurableCounter to reject a corrupt persisted index (never silently reset to 0)")
	}
}

func itoa(v uint64) string {
	return strconvFormatUint(v)
}

// strconvFormatUint is a tiny local helper so the test reads cleanly.
func strconvFormatUint(v uint64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}
