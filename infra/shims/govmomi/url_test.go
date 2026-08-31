package main

import (
	"strings"
	"testing"
)

// TestParseVCenterURL pins parseVCenterURL — the one CLI-only, non-vcsim-reachable
// piece of real logic in this shim (it never sees the simulator, so it needs
// direct coverage). It is the operator-facing -url/-username/-password contract
// documented in README.md's env/flag table, and it does three things:
//
//   - scheme defaulting: a bare host (no "://") becomes https://
//   - /sdk path injection: an empty or bare "/" path becomes /sdk
//   - credential layering: -username/-password override any userinfo already in
//     -url — UserPassword when both are set, User when only a username is given,
//     and userinfo already in the URL is left untouched only when no -username is
//     passed.
//
// It uses only net/url string parsing (no govmomi, no network, no simulator).
func TestParseVCenterURL(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		username string
		password string
		wantURL  string // String() of the returned *url.URL (userinfo redacted by url pkg)
		wantUser string // Username() of u.User ("" when nil)
		wantPass string // Password() of u.User
		wantSet  bool   // whether a password was set on u.User
	}{
		{
			// Bare host: scheme defaults to https, path defaults to /sdk.
			name:    "bare host",
			raw:     "vcenter.lab.example",
			wantURL: "https://vcenter.lab.example/sdk",
		},
		{
			// host:port stays put; scheme + /sdk still injected.
			name:    "host and port",
			raw:     "vcenter.lab.example:8443",
			wantURL: "https://vcenter.lab.example:8443/sdk",
		},
		{
			// Full https URL with no path gets /sdk appended.
			name:    "full https no path",
			raw:     "https://vcenter.lab.example",
			wantURL: "https://vcenter.lab.example/sdk",
		},
		{
			// A bare "/" path is treated as empty and replaced with /sdk.
			name:    "full https root path",
			raw:     "https://vcenter.lab.example/",
			wantURL: "https://vcenter.lab.example/sdk",
		},
		{
			// An explicit /sdk path is preserved verbatim (not doubled).
			name:    "full https with sdk path",
			raw:     "https://vcenter.lab.example/sdk",
			wantURL: "https://vcenter.lab.example/sdk",
		},
		{
			// A non-empty, non-root path is left untouched (no /sdk override).
			name:    "full https custom path preserved",
			raw:     "https://vcenter.lab.example/custom/endpoint",
			wantURL: "https://vcenter.lab.example/custom/endpoint",
		},
		{
			// An explicit http scheme is honored (not forced to https).
			name:    "explicit http scheme honored",
			raw:     "http://vcenter.lab.example",
			wantURL: "http://vcenter.lab.example/sdk",
		},
		{
			// username only => url.User (no password component).
			name:     "username only",
			raw:      "vcenter.lab.example",
			username: "administrator@vsphere.local",
			wantURL:  "https://administrator%40vsphere.local@vcenter.lab.example/sdk",
			wantUser: "administrator@vsphere.local",
			wantSet:  false,
		},
		{
			// username + password => url.UserPassword (both components set).
			name:     "username and password",
			raw:      "vcenter.lab.example",
			username: "administrator@vsphere.local",
			password: "s3cr3t",
			wantURL:  "https://administrator%40vsphere.local:s3cr3t@vcenter.lab.example/sdk",
			wantUser: "administrator@vsphere.local",
			wantPass: "s3cr3t",
			wantSet:  true,
		},
		{
			// Precedence: -username+-password override userinfo already in -url
			// (the flag wins, and it wins as UserPassword when both are given).
			name:     "flags override url userinfo both",
			raw:      "https://olduser:oldpass@vcenter.lab.example/sdk",
			username: "newuser",
			password: "newpass",
			wantURL:  "https://newuser:newpass@vcenter.lab.example/sdk",
			wantUser: "newuser",
			wantPass: "newpass",
			wantSet:  true,
		},
		{
			// Precedence: -username alone overrides in-url userinfo and drops the
			// in-url password (User, not UserPassword) — the flag is authoritative.
			name:     "username flag overrides url userinfo, drops password",
			raw:      "https://olduser:oldpass@vcenter.lab.example/sdk",
			username: "newuser",
			wantURL:  "https://newuser@vcenter.lab.example/sdk",
			wantUser: "newuser",
			wantSet:  false,
		},
		{
			// No -username: userinfo already present in -url is left untouched.
			name:     "url userinfo preserved when no username flag",
			raw:      "https://olduser:oldpass@vcenter.lab.example/sdk",
			wantURL:  "https://olduser:oldpass@vcenter.lab.example/sdk",
			wantUser: "olduser",
			wantPass: "oldpass",
			wantSet:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := parseVCenterURL(tt.raw, tt.username, tt.password)
			if err != nil {
				t.Fatalf("parseVCenterURL(%q, %q, %q) error: %v", tt.raw, tt.username, tt.password, err)
			}
			if got := u.String(); got != tt.wantURL {
				t.Errorf("URL = %q, want %q", got, tt.wantURL)
			}

			// Path is always /sdk-normalized or a preserved custom path — never empty.
			if u.Path == "" {
				t.Errorf("path is empty; parseVCenterURL must inject /sdk or preserve a path")
			}

			// Userinfo assertions.
			if tt.wantUser == "" {
				if u.User != nil {
					t.Errorf("u.User = %v, want nil (no username flag, no in-url userinfo)", u.User)
				}
				return
			}
			if u.User == nil {
				t.Fatalf("u.User is nil, want username %q", tt.wantUser)
			}
			if got := u.User.Username(); got != tt.wantUser {
				t.Errorf("username = %q, want %q", got, tt.wantUser)
			}
			gotPass, gotSet := u.User.Password()
			if gotSet != tt.wantSet {
				t.Errorf("password set = %v, want %v", gotSet, tt.wantSet)
			}
			if gotSet && gotPass != tt.wantPass {
				t.Errorf("password = %q, want %q", gotPass, tt.wantPass)
			}
		})
	}
}

// TestParseVCenterURLParseError pins the error wrapper: a syntactically invalid
// URL surfaces the operator-facing `parse vCenter URL %q: %w` context (control
// characters make url.Parse fail even after the https:// scheme is prepended).
func TestParseVCenterURLParseError(t *testing.T) {
	// A control character in the host is rejected by url.Parse.
	_, err := parseVCenterURL("host\x7f.example", "", "")
	if err == nil {
		t.Fatalf("parseVCenterURL of a malformed URL should error, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "parse vCenter URL") {
		t.Errorf("error = %q, want it to carry the 'parse vCenter URL' wrapper", got)
	}
}
