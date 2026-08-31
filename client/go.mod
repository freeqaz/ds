// Module path follows the repo-wide scheme:
// github.com/dream-serpent/dream-serpent/<tree>.
//
// LEAN DEFAULT — recorded as this workstream's first revisitable decision
// (design Part 3): one Go module for CLI + wrapper + TUI + goldentrace.
// Split only when a real dependency-weight or release-cadence pressure
// appears (the goldentrace harness is the likeliest first split).
//
// Dependency policy at skeleton time: STANDARD LIBRARY ONLY, so the
// workspace builds offline. Pinned choices are recorded, not declared,
// until the relevant freeze lands:
//
//   - github.com/dream-serpent/dream-serpent/proto/gen/go — the ONLY
//     cross-tree Go import this module may ever take; arrives when
//     dreamserpent.attach.v1 freezes at M0 (D38).
//   - The Claude Code adapter pins the CC version it parses via the
//     golden image (D49) — a fixture/runtime pin, never a go.mod entry.
//   - TUI framework choice is owner-landed with the first TUI PR.
//
// Never depended on from here: dataplane/ sources, boundary/ (harness),
// paid/ — and no secret-digest material ever reaches this module
// (doc 16 §6.5: attach-side scanning runs orchestrator-side).
module github.com/dream-serpent/dream-serpent/client

go 1.25.11
