// SPDX-License-Identifier: Apache-2.0

// Package pol2reachability is the POL-2 done-when conformance suite: the
// pack-driven reachability matrix that proves the developer-value test of the
// D64/D74 baseline policy pack — "a fresh session can call the Anthropic API,
// clone/push GitHub, and install npm packages with zero configuration, and can
// reach nothing else" (doc 09 §1/§6 POL-2 done-when, doc 13 §3/§7).
//
// The suite is deliberately split into two halves that share ONE matrix
// (matrix.go), so the offline assertions and the live runs prove the same
// claims:
//
//   - Offline half (runs today, no network, no live services). A purpose-built
//     reader (pack.go) over the FROZEN D74 v2 pack contents asserts the
//     contract every fresh install must satisfy before a flow is ever made:
//     tier defaults (core/vcs/packages enabled; telemetry/binary-cdn/ghcr/lfs
//     disabled-by-default), downloads.claude.ai excluded-because-pinned, the
//     D17 pass-through list empty, mandatory provenance_source_url on every
//     entry, a canary non-pack domain matching nothing, and the path-scoped
//     storage.googleapis.com entry held domain-inert behind requires:
//     http-policy until TLS-6 (doc 13 §1.7/§3, D74). These run as the
//     table-driven reachability matrix so the live half reuses it verbatim.
//
//   - Live half (env-gated, DEFERRED MANUAL). Gated behind DS_POL2_LIVE=1 and
//     SKIPPED BY DEFAULT, the live runners drive the documented client wire
//     shapes against a real fresh install + pack only: an Anthropic streaming
//     call, git clone/fetch/push, gh api, npm/yarn-classic/pnpm-via-corepack
//     installs, canary refusal at DNS-3 and TLS-1, the zero-flows-outside-pack
//     audit, and the TLS-6-present/absent capability-gate paths. They are
//     scaffolded against the SAME matrix and never run in CI — they are the
//     deferred manual conformance pass owned by the boundary rig.
//
// This package carries NO live secrets and NO recorded traffic (D50): the pack
// fixture (pack.go) is a synthetic, clearly-labeled transcription of the frozen
// D74 pack enumerated in doc 13 §3 ("Baseline pack contents v2") and the doc 04
// §6 D74 decision-log row — it is the spec made executable, not a copy of any
// shipped artifact. It feeds roadmap task 01KTWJ6Y0GE9A0WEC6Z4XHNB8M.
//
// Governing decisions: D64 (system default baseline), D74 (tiered pack v2 +
// provenance + capability gating), D17 (TLS-termination / empty pass-through),
// D70 (QUIC reject — udp/443 outside the reachability set), D26/D51 (the
// guardrail suite ships runnable with the OSS data plane). Network prose uses
// egress-gateway / TLS-termination vocabulary throughout.
package pol2reachability
