// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

// capsAmbientIsSet is the non-Linux stub: no procfs, no prctl ambient caps, so
// the probe reports "not set" (fail-closed). The helper only ever runs
// privileged on the Linux dogfood host; this keeps the package `go build`-able
// and testable on any GOOS (the pure parseProcCaps table tests still run).
func capsAmbientIsSet(capBit uintptr) bool { return false }
