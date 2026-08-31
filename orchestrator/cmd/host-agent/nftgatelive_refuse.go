// SPDX-License-Identifier: Apache-2.0

//go:build nftgatelive

// nftgatelive_refuse.go is a COMPILE-REFUSAL guard, not code. It is excluded
// from every normal build (the `nftgatelive` tag selects it), so it costs the
// default build nothing; a build that DOES pass `-tags nftgatelive` fails to
// compile with an error naming the rule it broke.
//
// WHY. D148 re-froze the doc 14 §6 linker set: only ds-dnsgate and ds-nethelper
// link the ds-nft write path, and the host agent invokes ds-nethelper and runs
// fully unprivileged. Re-linking the cgo edge here would silently hand this
// process CAP_NET_ADMIN again and re-create the privilege model the ratified
// decision removed. Because seams.go no longer imports internal/nftbridge, a
// tagged agent build otherwise gets no further than a confusing missing-libds_nft
// LINK error (or, worse, succeeds on a box where the staticlib happens to be
// staged); this file makes it a loud, self-explaining COMPILE error instead —
// and needs no cgo, no staticlib, and no toolchain to fire.

package main

// The identifier below is deliberately UNDEFINED: it is the error message.
var _ = hostAgentMustNeverBuildWithNftgatelive_D148_buildDsNethelperInstead
