// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// ambient_other.go is the non-Linux compile stub for the ambient CAP_NET_ADMIN
// bracket. Ambient capabilities are a Linux concept and the privileged helper
// only ever runs on the Linux dogfood host, so off Linux the bracket FAILS
// CLOSED: the wrapped backend call is never invoked. This keeps the package
// `go build`-able on any GOOS (the same posture caps_other.go takes for the
// read-only probe) without ever pretending a capability was propagated.

package main

import "fmt"

// withAmbientNetAdmin refuses on non-Linux: f is NEVER invoked.
func withAmbientNetAdmin(_ func() error) error {
	return fmt.Errorf("ds-nethelper: ambient CAP_NET_ADMIN propagation is Linux-only; the privileged backend is refused on this platform (fail-closed)")
}
