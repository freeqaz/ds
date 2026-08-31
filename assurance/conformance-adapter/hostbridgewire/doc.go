// SPDX-License-Identifier: Apache-2.0

// Package hostbridgewire is the CROSS-TREE conformance pin for the host-agent
// bridge's framed-UDS wire contract — the numbers, reject codes, JSON tags, and
// framing that client/hostbridge/socket.go DEFINES and the orchestrator relay
// legs HAND-MIRROR. The orchestrator single-sources that mirror in
// orchestrator/cmd/orchestrator/wire.go — BOTH the write leg (drivesink_live.go)
// and the read leg (contentsource_live.go) speak it — so pinning that ONE file
// covers both legs' full wire surface (incl. the read-leg resume ring).
//
// WHY THIS EXISTS. The import boundary (D26/D80) forbids the orchestrator tree
// from importing client/hostbridge, so wire.go re-declares the frame numbers,
// reject codes, and wire JSON tags as its own const block + wire structs. Two
// independent copies of a wire contract drift silently: a renumber in socket.go
// (say frameInput 5 → 6) compiles clean on both sides and fails only at LIVE
// runtime, when a driven keystroke lands as the wrong frame. This package is the
// assurance seam D26/D80 explicitly permits — the one place allowed to read BOTH
// trees — so that drift turns a build RED instead.
//
// HOW IT PINS. The two trees cannot be linked at compile time here (client/ does
// not build standalone — it resolves proto/gen/go only through go.work — and the
// orchestrator relay legs live in package main, unimportable). So the pin reads
// each tree's SOURCE from disk and asserts every mirrored constant + JSON tag
// equals the documented golden (testdata/hostbridge_wire.golden.json) and agrees
// across the two trees. Mutating a mirrored constant on EITHER side turns the pin
// RED (proven by temporary mutation during development; see the task note).
//
// TEST-CACHE CORRECTNESS. The reads go THROUGH symlinks under testdata/srclinks
// (SourceLinks), never via ../../ paths directly. Go's test cache hashes only files
// opened at paths lexically inside this module's root (cmd/go computeTestInputsID:
// "Do not recheck files outside the module"), so a direct cross-tree read lets a
// warm cache serve a stale PASS after a renumber in client/ or orchestrator/ —
// exactly the drift this package exists to catch. The in-module link path IS
// tracked, and the open FOLLOWS the link, so the tracked size+mtime are the real
// file's and the pin re-runs the moment either tree's source changes (verified
// empirically: with a warm cache, a socket.go mutation re-runs and REDs this
// package). TestSourceLinksResolve pins each link's target so a stale COPY cannot
// silently replace a link.
//
// The golden also carries the exact on-wire bytes of representative frames
// (type byte, 4-byte big-endian length, payload); FrameBytes renders them so the
// pin catches a framing change, not only a number change.
//
// This module is OSS and carries no guardrail assertions of its own (D51): it is
// a drift trap over two trees' documented wire, not a production import of either.
package hostbridgewire
