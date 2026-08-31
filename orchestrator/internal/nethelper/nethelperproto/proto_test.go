// SPDX-License-Identifier: Apache-2.0

package nethelperproto

import (
	"strings"
	"testing"
)

func TestValidateOp(t *testing.T) {
	tests := []struct {
		name string
		op   string
		ok   bool
	}{
		{"probe", OpProbe, true},
		{"create-tap", OpCreateTap, true},
		{"delete-tap", OpDeleteTap, true},
		{"instantiate-session", OpInstantiateSession, true},
		{"flush-session", OpFlushSession, true},
		{"teardown-session", OpTeardownSession, true},
		{"empty", "", false},
		{"unknown", "apply-ruleset", false},
		{"case-sensitive", "Create-Tap", false},
		{"flag-shaped", "--create-tap", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOp(tt.op)
			if (err == nil) != tt.ok {
				t.Fatalf("ValidateOp(%q) err=%v, want ok=%v", tt.op, err, tt.ok)
			}
		})
	}
}

func TestValidateCreateTap(t *testing.T) {
	const caller = uint32(1000)
	good := CreateTapParams{TapName: "dstap-7", OwnerUID: caller, HostSessionIndex: 7}
	tests := []struct {
		name    string
		mutate  func(*CreateTapParams)
		wantErr string // substring; empty = valid
	}{
		{"good minimal", func(p *CreateTapParams) {}, ""},
		{"good with mac", func(p *CreateTapParams) { p.GuestMAC = "52:54:00:12:34:56" }, ""},
		{"good index zero", func(p *CreateTapParams) { p.TapName = "dstap-0"; p.HostSessionIndex = 0 }, ""},
		{"good routed ceiling", func(p *CreateTapParams) { p.TapName = "dstap-255"; p.HostSessionIndex = 255 }, ""},
		{"empty tap name", func(p *CreateTapParams) { p.TapName = "" }, "empty"},
		{"bad prefix", func(p *CreateTapParams) { p.TapName = "dstab-7" }, "does not match"},
		{"leading zero", func(p *CreateTapParams) { p.TapName = "dstap-07" }, "does not match"},
		{"trailing junk", func(p *CreateTapParams) { p.TapName = "dstap-7;rm" }, "does not match"},
		{"ifnamsiz overflow", func(p *CreateTapParams) { p.TapName = "dstap-7777777777"; p.HostSessionIndex = 7 }, "IFNAMSIZ"},
		{"index mismatch", func(p *CreateTapParams) { p.HostSessionIndex = 8 }, "disagrees"},
		{"over routed ceiling", func(p *CreateTapParams) { p.TapName = "dstap-256"; p.HostSessionIndex = 256 }, "ceiling"},
		{"root owner", func(p *CreateTapParams) { p.OwnerUID = 0 }, "root"},
		{"foreign owner", func(p *CreateTapParams) { p.OwnerUID = caller + 1 }, "invoking uid"},
		{"mac uppercase", func(p *CreateTapParams) { p.GuestMAC = "52:54:00:12:34:AB" }, "lowercase"},
		{"mac short", func(p *CreateTapParams) { p.GuestMAC = "52:54:00:12:34" }, "lowercase"},
		{"mac junk", func(p *CreateTapParams) { p.GuestMAC = "not-a-mac" }, "lowercase"},
		{"mac all zero", func(p *CreateTapParams) { p.GuestMAC = "00:00:00:00:00:00" }, "all-zero"},
		{"mac multicast", func(p *CreateTapParams) { p.GuestMAC = "01:00:5e:00:00:01" }, "multicast"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := good
			tt.mutate(&p)
			err := ValidateCreateTap(p, caller)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateSession(t *testing.T) {
	tests := []struct {
		name    string
		p       SessionParams
		wantErr string
	}{
		{"good", SessionParams{TapName: "dstap-7", HostSessionIndex: 7}, ""},
		{"good mark-space ceiling", SessionParams{TapName: "dstap-16383", HostSessionIndex: 16383}, ""},
		{"over mark-space ceiling", SessionParams{TapName: "dstap-16384", HostSessionIndex: 16384}, "ceiling"},
		{"mismatch", SessionParams{TapName: "dstap-7", HostSessionIndex: 8}, "disagrees"},
		{"empty", SessionParams{}, "empty"},
		{"not dstap", SessionParams{TapName: "eth0", HostSessionIndex: 0}, "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSession(tt.p)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// The teardown-side verbs must accept every index create-tap ever could
// (routed ceiling ⊂ mark-space ceiling) — a session that was created must
// always be teardown-able through the same boundary.
func TestTeardownCeilingCoversCreateCeiling(t *testing.T) {
	if MaxRoutedSessionIndex > MaxHostSessionIndex {
		t.Fatalf("routed ceiling %d exceeds mark-space ceiling %d", MaxRoutedSessionIndex, MaxHostSessionIndex)
	}
}

// TestValidateTablePresent pins the trust-boundary gate on the read-only
// table-present verb: a plausible nft identifier passes, and empty / oversized /
// shell-ish / uppercase input is REJECTED at validation rather than reaching the
// exec. Injection is not the risk (the helper execs nft via argv, never a shell)
// — the point is that a malformed request fails as a validation error instead of
// masquerading as "the floor table is absent", which the agent would treat as a
// fail-closed not-ready verdict and which is far harder to diagnose.
func TestValidateTablePresent(t *testing.T) {
	for _, ok := range []string{"ds_boundary", "ds_resolver_closure", "ds_proxy_out", "a"} {
		if err := ValidateTablePresent(TablePresentParams{Table: ok}); err != nil {
			t.Errorf("ValidateTablePresent(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",                     // empty
		"ds boundary",          // space
		"ds;nft flush ruleset", // shell-ish
		"ds/boundary",          // path separator
		"DS_BOUNDARY",          // uppercase
		"1table",               // leading digit
		"-flag",                // could be read as an nft flag
		"ds_boundary_with_a_name_far_over_the_thirty_two_char_ceiling",
	} {
		if err := ValidateTablePresent(TablePresentParams{Table: bad}); err == nil {
			t.Errorf("ValidateTablePresent(%q) = nil, want a rejection", bad)
		}
	}
}

// TestOpsIncludesTablePresent proves the dispatch whitelist carries the new verb —
// ValidateOp rejects anything absent from Ops(), so a const without a whitelist
// entry is a verb the helper refuses at the boundary.
func TestOpsIncludesTablePresent(t *testing.T) {
	if err := ValidateOp(OpTablePresent); err != nil {
		t.Errorf("ValidateOp(%q) = %v — the op is not in the dispatch whitelist", OpTablePresent, err)
	}
}
