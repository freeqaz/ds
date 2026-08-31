// SPDX-License-Identifier: Apache-2.0

package fakegen

import (
	"fmt"
	"os"
	"path/filepath"
)

// Generate builds the model for one service contract and emits its fake source.
// It is the single-call pipeline step a generator main invokes per seam.
func Generate(in Input) ([]byte, error) {
	model, err := BuildModel(in)
	if err != nil {
		return nil, err
	}
	return Emit(model)
}

// GenerateToFile runs Generate and writes the result to path, creating parent
// directories as needed. It is intentionally write-always (not compare-then-
// write): the codegen-drift gate (proto/FREEZE.md) re-runs this and diffs the
// committed tree, so the source of truth for "is this stale" is git, not a
// mtime here.
func GenerateToFile(in Input, path string) error {
	src, err := Generate(in)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("fakegen: mkdir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, src, 0o644); err != nil {
		return fmt.Errorf("fakegen: write %s: %w", path, err)
	}
	return nil
}
