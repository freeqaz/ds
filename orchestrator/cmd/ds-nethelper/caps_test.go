// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// bit12 is a CAP_NET_ADMIN-set hex mask; noCap has bit 12 clear. 0x...1000 is
// exactly (1<<12). fullSet is a typical root CapEff (all bits) — bit 12 set.
const (
	maskCapNetAdmin = "0000000000001000" // only CAP_NET_ADMIN
	maskNoCapNet    = "0000000000000800" // CAP_SYS_ADMIN (bit 11), not 12
	maskAllCaps     = "000001ffffffffff" // every cap incl. 12
	maskEmpty       = "0000000000000000"
)

func statusBody(eff, inh, prm string) string {
	// A representative /proc/self/status excerpt — only the Cap* lines are
	// parsed; the surrounding lines exercise the prefix scan.
	return "Name:\tds-nethelper\n" +
		"Uid:\t1000\t1000\t1000\t1000\n" +
		"CapInh:\t" + inh + "\n" +
		"CapPrm:\t" + prm + "\n" +
		"CapEff:\t" + eff + "\n" +
		"CapBnd:\t000001ffffffffff\n" +
		"Seccomp:\t0\n"
}

// TestParseProcCaps is the table test for every field the extended probe
// reports off /proc/<pid>/status — effective, inheritable, and the permitted
// leg that (with inheritable) predicts AmbientRaiseOK. Pure string parsing,
// zero kernel touch.
func TestParseProcCaps(t *testing.T) {
	tests := []struct {
		name                      string
		eff, inh, prm             string
		wantEff, wantInh, wantPrm bool
	}{
		{"eip fully configured", maskCapNetAdmin, maskCapNetAdmin, maskCapNetAdmin, true, true, true},
		{"ep only (inheritable clear)", maskCapNetAdmin, maskEmpty, maskCapNetAdmin, true, false, true},
		{"e only (permitted+inh clear)", maskCapNetAdmin, maskEmpty, maskEmpty, true, false, false},
		{"root all-caps", maskAllCaps, maskAllCaps, maskAllCaps, true, true, true},
		{"no cap_net_admin anywhere", maskNoCapNet, maskNoCapNet, maskNoCapNet, false, false, false},
		{"empty masks", maskEmpty, maskEmpty, maskEmpty, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eff, inh, prm := parseProcCaps(statusBody(tt.eff, tt.inh, tt.prm))
			if eff != tt.wantEff || inh != tt.wantInh || prm != tt.wantPrm {
				t.Fatalf("parseProcCaps = (eff=%v inh=%v prm=%v), want (%v %v %v)",
					eff, inh, prm, tt.wantEff, tt.wantInh, tt.wantPrm)
			}
		})
	}
}

// A missing or malformed Cap* line must yield false for that set — fail-closed,
// never a claimed-but-unproven capability.
func TestParseProcCapsMalformed(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{"no cap lines at all", "Name:\tx\nUid:\t0\t0\t0\t0\n"},
		{"non-hex mask", "CapEff:\tnothex\nCapInh:\t0\nCapPrm:\t0\n"},
		{"empty body", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eff, inh, prm := parseProcCaps(tt.status)
			if eff || inh || prm {
				t.Fatalf("malformed status yielded a true cap bit: eff=%v inh=%v prm=%v", eff, inh, prm)
			}
		})
	}
}

// capBitSet must key on bit 12 specifically — a neighbouring bit (11) set must
// not be mistaken for CAP_NET_ADMIN.
func TestCapBitSetPrecision(t *testing.T) {
	if capBitSet("CapEff:\t"+maskNoCapNet+"\n", "CapEff:") {
		t.Fatalf("CAP_SYS_ADMIN (bit 11) mask misread as CAP_NET_ADMIN (bit 12)")
	}
	if !capBitSet("CapEff:\t"+maskCapNetAdmin+"\n", "CapEff:") {
		t.Fatalf("CAP_NET_ADMIN (bit 12) mask not detected")
	}
}

// The AmbientRaiseOK derivation is permitted ∧ inheritable (the kernel
// PR_CAP_AMBIENT_RAISE precondition). This pins that logic against the parsed
// sets WITHOUT issuing any prctl (probeCaps() folds in a read-only IS_SET query
// on top; here we assert only the pure derivation the graft depends on).
func TestAmbientRaisePrecondition(t *testing.T) {
	tests := []struct {
		name     string
		inh, prm string
		wantOK   bool
	}{
		{"permitted and inheritable → raisable", maskCapNetAdmin, maskCapNetAdmin, true},
		{"inheritable only → not raisable", maskCapNetAdmin, maskEmpty, false},
		{"permitted only → not raisable", maskEmpty, maskCapNetAdmin, false},
		{"neither → not raisable", maskEmpty, maskEmpty, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, inh, prm := parseProcCaps(statusBody(maskEmpty, tt.inh, tt.prm))
			if got := prm && inh; got != tt.wantOK {
				t.Fatalf("ambient-raise precondition (prm∧inh) = %v, want %v", got, tt.wantOK)
			}
		})
	}
}

// TestBackendSignaturePin is the compile-time-asserted surface, exercised at
// runtime too: the stub backend must satisfy the pinned interface (this is the
// same guarantee `var _ backend = (*notBuiltBackend)(nil)` gives at build
// time — restated here so the test suite documents the drift guard, and so the
// five nftbridge-mirrored signatures are all invoked once through the interface
// and confirmed fail-closed).
func TestBackendSignaturePin(t *testing.T) {
	var be backend = newBackend() // stub; assignable ⇒ satisfies the pinned surface
	// Every verb, called through the interface, must fail closed ENOTBUILT —
	// the stub never touches the kernel. The hasUID bool on CreateTap is the
	// field-for-field nftbridge mirror the pin exists to hold.
	checks := []struct {
		name string
		call func() error
	}{
		{"CreateTap", func() error { return be.CreateTap("dstap-1", 1000, true, 1, "") }},
		{"DeleteTap", func() error { return be.DeleteTap("dstap-1") }},
		{"InstantiateSession", func() error { return be.InstantiateSession("dstap-1", 1) }},
		{"FlushSession", func() error { return be.FlushSession("dstap-1", 1) }},
		{"TeardownSession", func() error { return be.TeardownSession("dstap-1", 1) }},
	}
	for _, c := range checks {
		if err := c.call(); err != errNotBuilt {
			t.Fatalf("%s stub returned %v, want errNotBuilt (fail-closed, kernel-untouching)", c.name, err)
		}
	}
}
