// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperproto"
)

// fakeBackend records the ONE call it receives and returns a scripted error.
type fakeBackend struct {
	calls        []string
	err          error
	lastHasUID   bool // records the hasUID CreateTap was invoked with
	sawCreateTap bool
}

func (f *fakeBackend) CreateTap(name string, uid uint32, hasUID bool, idx uint32, mac string) error {
	f.calls = append(f.calls, "create-tap")
	f.lastHasUID, f.sawCreateTap = hasUID, true
	return f.err
}
func (f *fakeBackend) DeleteTap(name string) error {
	f.calls = append(f.calls, "delete-tap")
	return f.err
}
func (f *fakeBackend) InstantiateSession(name string, idx uint32) error {
	f.calls = append(f.calls, "instantiate-session")
	return f.err
}
func (f *fakeBackend) FlushSession(name string, idx uint32) error {
	f.calls = append(f.calls, "flush-session")
	return f.err
}
func (f *fakeBackend) TeardownSession(name string, idx uint32) error {
	f.calls = append(f.calls, "teardown-session")
	return f.err
}

func runHelper(t *testing.T, argv []string, stdin string, be backend, callerUID int) (int, nethelperproto.Result, string) {
	t.Helper()
	var out, errb bytes.Buffer
	exit := run(argv, strings.NewReader(stdin), &out, &errb, be, callerUID)
	var res nethelperproto.Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout is not one Result JSON line: %v (stdout=%q)", err, out.String())
	}
	return exit, res, errb.String()
}

func TestRunTable(t *testing.T) {
	const uid = 1000
	sess := `{"tap_name":"dstap-7","host_session_index":7}`
	tests := []struct {
		name      string
		argv      []string
		stdin     string
		beErr     error
		wantExit  int
		wantCode  string
		wantCalls int
	}{
		{"no argv", nil, "", nil, nethelperproto.ExitValidation, nethelperproto.CodeValidation, 0},
		{"two ops", []string{"probe", "probe"}, "", nil, nethelperproto.ExitValidation, nethelperproto.CodeValidation, 0},
		{"unknown op", []string{"apply-nft"}, "", nil, nethelperproto.ExitValidation, nethelperproto.CodeValidation, 0},
		{"probe ok", []string{"probe"}, "", nil, nethelperproto.ExitOK, nethelperproto.CodeOK, 0},

		{"create ok", []string{"create-tap"}, `{"tap_name":"dstap-7","owner_uid":1000,"host_session_index":7}`, nil, nethelperproto.ExitOK, nethelperproto.CodeOK, 1},
		{"create foreign uid rejected pre-backend", []string{"create-tap"}, `{"tap_name":"dstap-7","owner_uid":1001,"host_session_index":7}`, nil, nethelperproto.ExitValidation, nethelperproto.CodeValidation, 0},
		{"create idx mismatch rejected pre-backend", []string{"create-tap"}, `{"tap_name":"dstap-7","owner_uid":1000,"host_session_index":8}`, nil, nethelperproto.ExitValidation, nethelperproto.CodeValidation, 0},
		{"create unknown field rejected", []string{"create-tap"}, `{"tap_name":"dstap-7","owner_uid":1000,"host_session_index":7,"ruleset":"flush ruleset"}`, nil, nethelperproto.ExitProtocol, nethelperproto.CodeProtocol, 0},
		{"create trailing data rejected", []string{"create-tap"}, `{"tap_name":"dstap-7","owner_uid":1000,"host_session_index":7}{}`, nil, nethelperproto.ExitProtocol, nethelperproto.CodeProtocol, 0},
		{"create empty stdin rejected", []string{"create-tap"}, ``, nil, nethelperproto.ExitProtocol, nethelperproto.CodeProtocol, 0},
		{"create backend fault", []string{"create-tap"}, `{"tap_name":"dstap-7","owner_uid":1000,"host_session_index":7}`, errors.New("ds-nft create_tap failed (rc=-2)"), nethelperproto.ExitBackend, nethelperproto.CodeBackend, 1},
		{"create not built", []string{"create-tap"}, `{"tap_name":"dstap-7","owner_uid":1000,"host_session_index":7}`, errNotBuilt, nethelperproto.ExitNotBuilt, nethelperproto.CodeNotBuilt, 1},

		{"delete ok", []string{"delete-tap"}, sess, nil, nethelperproto.ExitOK, nethelperproto.CodeOK, 1},
		{"instantiate ok", []string{"instantiate-session"}, sess, nil, nethelperproto.ExitOK, nethelperproto.CodeOK, 1},
		{"flush ok", []string{"flush-session"}, sess, nil, nethelperproto.ExitOK, nethelperproto.CodeOK, 1},
		{"teardown ok", []string{"teardown-session"}, sess, nil, nethelperproto.ExitOK, nethelperproto.CodeOK, 1},
		{"session idx over ceiling", []string{"flush-session"}, `{"tap_name":"dstap-16384","host_session_index":16384}`, nil, nethelperproto.ExitValidation, nethelperproto.CodeValidation, 0},
		{"session name not dstap", []string{"delete-tap"}, `{"tap_name":"eth0","host_session_index":0}`, nil, nethelperproto.ExitValidation, nethelperproto.CodeValidation, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &fakeBackend{err: tt.beErr}
			exit, res, audit := runHelper(t, tt.argv, tt.stdin, be, uid)
			if exit != tt.wantExit {
				t.Fatalf("exit=%d want %d (result=%+v)", exit, tt.wantExit, res)
			}
			if res.Code != tt.wantCode {
				t.Fatalf("code=%q want %q (msg=%q)", res.Code, tt.wantCode, res.Message)
			}
			if res.V != nethelperproto.ProtocolVersion {
				t.Fatalf("result v=%d want %d", res.V, nethelperproto.ProtocolVersion)
			}
			if got := len(be.calls); got != tt.wantCalls {
				t.Fatalf("backend calls=%v want %d (a rejected request must never reach the privileged seam)", be.calls, tt.wantCalls)
			}
			if audit == "" {
				t.Fatalf("no audit line on stderr")
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(audit), &rec); err != nil {
				t.Fatalf("audit line is not one JSON object: %v (%q)", err, audit)
			}
			if rec["code"] != tt.wantCode {
				t.Fatalf("audit code=%v want %q", rec["code"], tt.wantCode)
			}
		})
	}
}

// A valid create-tap must always reach the backend with hasUID=true: the
// owner_uid==caller rule (validated upstream) means the tap is always owned,
// and the hasUID bool rides the nftbridge signature pin so the deferred live
// pass-through stays field-exact. hasUID=false (an unowned tap) must never be
// synthesizable through this boundary.
func TestCreateTapAlwaysOwned(t *testing.T) {
	be := &fakeBackend{}
	exit, _, _ := runHelper(t, []string{"create-tap"},
		`{"tap_name":"dstap-7","owner_uid":1000,"host_session_index":7}`, be, 1000)
	if exit != nethelperproto.ExitOK {
		t.Fatalf("valid create-tap exit=%d want %d", exit, nethelperproto.ExitOK)
	}
	if !be.sawCreateTap {
		t.Fatalf("backend CreateTap was never invoked")
	}
	if !be.lastHasUID {
		t.Fatalf("create-tap reached backend with hasUID=false; the boundary must always mint OWNED taps")
	}
}

// The probe must truthfully report the stub build (built=false) — an agent
// composing readiness on it must see fail-closed, never a vacuous ready.
func TestProbeReportsNotBuiltOnStub(t *testing.T) {
	be := &fakeBackend{}
	exit, res, _ := runHelper(t, []string{"probe"}, "", be, 1000)
	if exit != nethelperproto.ExitOK || !res.OK {
		t.Fatalf("probe failed: exit=%d res=%+v", exit, res)
	}
	if res.Built {
		t.Fatalf("stub build reports built=true")
	}
	if len(be.calls) != 0 {
		t.Fatalf("probe touched the privileged seam: %v", be.calls)
	}
}

// Oversized stdin params are a protocol fault, rejected before validation.
func TestOversizedParamsRejected(t *testing.T) {
	big := `{"tap_name":"dstap-7","host_session_index":7,"pad":"` + strings.Repeat("x", nethelperproto.MaxParamsBytes) + `"}`
	be := &fakeBackend{}
	exit, res, _ := runHelper(t, []string{"flush-session"}, big, be, 1000)
	if exit != nethelperproto.ExitProtocol || res.Code != nethelperproto.CodeProtocol {
		t.Fatalf("oversized params not rejected as protocol fault: exit=%d code=%q", exit, res.Code)
	}
	if len(be.calls) != 0 {
		t.Fatalf("oversized params reached the backend")
	}
}
