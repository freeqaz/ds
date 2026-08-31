// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package entrypoint

import "errors"

// pty_other.go is the non-Linux stub of the pty launch mode (the terminal-MVP
// rider, docs/serpent-cli-mvp/10-build-decisions §A3 res. 7). The pty primitives
// (openPTY, controlling-tty exec, TIOCSWINSZ) are Linux-only — the guest is always
// Linux — but the vm/ module must cross-build clean (darwin in particular), so
// this stub provides a ptyLauncher whose start fails closed with errPtyUnsupported
// instead of breaking the build on non-Linux platforms.

// errPtyUnsupported is returned by ptyLauncher.start on a non-Linux platform.
var errPtyUnsupported = errors.New("pty launch mode is only supported on linux")

// ptyLauncher mirrors the Linux launcher's shape (so chooseLauncher in run.go is
// build-tag-agnostic) but is inert off Linux: start fails closed.
type ptyLauncher struct {
	initialWinsize winsize
}

func (ptyLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	return nil, runtimeStdio{}, errPtyUnsupported
}
