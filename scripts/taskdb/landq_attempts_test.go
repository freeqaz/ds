// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

// TestTransientCapHit pins the per-row transient-gate attempt cap boundary: a
// TRANSIENT gate failure (timeout / missing toolchain / signal death) requeues a
// row until it has been claimed maxAttempts times, then parks it 'failed' so a
// gate that can never RUN cannot starve the head of the serial landing queue
// forever. claimNextLand bumps attempts on every claim, so `attempts` is the
// count INCLUDING the claim that produced the current failure.
func TestTransientCapHit(t *testing.T) {
	cases := []struct {
		name        string
		attempts    int
		maxAttempts int
		want        bool
	}{
		{"first attempt under cap", 1, 5, false},
		{"just under cap", 4, 5, false},
		{"at cap parks", 5, 5, true},
		{"over cap parks", 6, 5, true},
		{"cap of 1 parks on first", 1, 1, true},
		{"zero = unbounded never caps", 9999, 0, false},
		{"negative = unbounded never caps", 9999, -1, false},
		{"cap with zero attempts (defensive)", 0, 5, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := transientCapHit(c.attempts, c.maxAttempts); got != c.want {
				t.Errorf("transientCapHit(attempts=%d, max=%d) = %v, want %v",
					c.attempts, c.maxAttempts, got, c.want)
			}
		})
	}
}
