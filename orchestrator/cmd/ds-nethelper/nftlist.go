// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// nftListTimeout bounds the read-only nft shell-out. The helper is forked
// per-op by the agent's readiness probe, which is itself on the CreateSession
// admission path, so a hung nft must not wedge session creation.
const nftListTimeout = 5 * time.Second

// listTableInet reports whether `inet <table>` exists, via a read-only
// `nft list table inet <table>`. nil => present.
//
// This runs INSIDE the helper on purpose: nft needs CAP_NET_ADMIN just to
// initialise its netlink cache ("Operation not permitted (you must be root)"),
// so the same call from the unprivileged D148 agent reports every table absent
// and fails readiness closed for a floor that is actually installed.
//
// argv exec, never a shell — the table name is one argument, so it cannot be
// interpreted. Output is discarded: presence is the exit status. Nothing is
// mutated (`list` is read-only), so this verb cannot alter the floor it reports on.
func listTableInet(table string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nftListTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "list", "table", "inet", table)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("nft list table inet %s timed out after %s", table, nftListTimeout)
		}
		return fmt.Errorf("nft list table inet %s: %v (%s)", table, err, firstLine(out))
	}
	return nil
}

// firstLine trims nft's output to its first line for a one-line Message.
func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}
