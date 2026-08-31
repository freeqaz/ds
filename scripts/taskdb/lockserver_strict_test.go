// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

// strictGateError is the `lockserver check --strict` wave pre-flight decision.
// It must fail ONLY when cross-clone locking is enabled-but-unusable, so a wave
// never dispatches blind to other clones/machines, while staying a no-op for
// deliberate solo work and a healthy server.
func TestStrictGate(t *testing.T) {
	cases := []struct {
		name                   string
		enabled, reach, schema bool
		wantErr                bool
		wantSubstr             string
	}{
		{"disabled passes", false, false, false, false, ""},
		{"disabled passes even if 'reachable'", false, true, true, false, ""},
		{"enabled+reachable+schema passes", true, true, true, false, ""},
		{"enabled unreachable fails", true, false, false, true, "UNREACHABLE"},
		{"enabled reachable no schema fails", true, true, false, true, "schema MISSING"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := strictGateError(c.enabled, c.reach, c.schema, "ssh -N -L 5433:...")
			if c.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if c.wantSubstr != "" && !strings.Contains(err.Error(), c.wantSubstr) {
				t.Fatalf("error %q missing %q", err, c.wantSubstr)
			}
		})
	}
}
