// SPDX-License-Identifier: Apache-2.0

// Package conformanceadapter wires the real Rust data plane (dataplane/:
// ds-dnsgate, ds-tlsproxy, ds-flowlog, and the ds-nft ruleset) behind the Go
// interface seams of the boundary/ TDD harness — the executable specification
// of the boundary's guarantees (D26, doc 06 §2.2).
//
// The boundary/ suite is RED by design: every seam is a stub and every test
// asserts the real documented outcome. This module turns it green one
// guardrail at a time by implementing those seams over the wire against the
// real services, without the spec ever importing production code (or vice
// versa).
//
// It also hosts the proxy wire-conformance matrix (doc 06 §2.2): real-client
// runs with curl, npm, and git-over-HTTPS, a cert-pinned client that must hit
// the D17 pass-through list, and a DoH client that must be blocked — plus
// golden-trace diffs of recorded exchanges.
//
// This module is OSS so anyone can run the D26 spec against an OSS data-plane
// deployment (D51). It carries no guardrail assertions of its own: the spec
// lives in boundary/, the published claims package in
// assurance/guardrail-conformance/. See README.md in this directory.
package conformanceadapter
