// Package gen is the root of the generated-Go contract module.
//
// Everything under proto/gen/go is buf-codegen output (see ../../buf.gen.yaml):
// per-package stubs land in subdirectories mirroring the proto tree
// (e.g. dreamserpent/orchestrator/v1) together with generated programmable
// fakes, which publish FIRST (doc 05 OQ3). This module is the ONLY Go import
// allowed across workstream seams — including from paid/ (D80; CI-enforced by
// the oss-manifest gate). No hand-written code lives here beyond this doc file.
//
// Module path scheme: github.com/dream-serpent/dream-serpent/proto/gen/go.
package gen
