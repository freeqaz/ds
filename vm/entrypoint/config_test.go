// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
	"google.golang.org/protobuf/proto"
)

// validProto returns a minimal, valid EntrypointConfig proto for tests to mutate.
func validProto() *runtimev1.EntrypointConfig {
	return &runtimev1.EntrypointConfig{
		SessionRef: &v1.SessionRef{
			SessionUuid: "sess-uuid-1",
			HostId:      "host-1",
			TapName:     "dstap-1",
		},
		Launch: &runtimev1.LaunchSpec{
			Command:    "/usr/local/bin/claude",
			Args:       []string{"--print"},
			Env:        []string{"FOO=bar"},
			WorkingDir: "/work",
		},
		Posture: runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD,
		Attach:  &runtimev1.AttachWiring{EventSocketPath: "/run/ds/attach.sock"},
		Egress: &runtimev1.EgressWiring{
			HttpProxy:    "127.0.0.1:18080",
			HttpsProxy:   "127.0.0.1:18080",
			NoProxy:      []string{"127.0.0.1", "::1"},
			CaBundlePath: "/etc/ds/ca-bundle.pem",
		},
		SessionTokenEndpoint: "http://169.254.0.2:8080/token",
	}
}

// writeConfigDir marshals pb into <dir>/config.pb and returns an env getter
// pointing DS_ENTRYPOINT_CONFIG_DIR at it.
func writeConfigDir(t *testing.T, pb *runtimev1.EntrypointConfig) func(string) string {
	t.Helper()
	dir := t.TempDir()
	raw, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFileName), raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return func(k string) string {
		if k == configDirEnv {
			return dir
		}
		return ""
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	getenv := writeConfigDir(t, validProto())
	cfg, err := loadConfig(getenv)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.session.sessionUUID != "sess-uuid-1" {
		t.Errorf("sessionUUID = %q", cfg.session.sessionUUID)
	}
	if cfg.launch.command != "/usr/local/bin/claude" {
		t.Errorf("command = %q", cfg.launch.command)
	}
	if cfg.posture != posturePermissionStandard {
		t.Errorf("posture = %v", cfg.posture)
	}
	if cfg.egress.caBundlePath != "/etc/ds/ca-bundle.pem" {
		t.Errorf("caBundlePath = %q", cfg.egress.caBundlePath)
	}
}

func TestLoadConfig_FailClosed_UnsetEnv(t *testing.T) {
	_, err := loadConfig(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected fail-closed error for unset env")
	}
	if !strings.Contains(err.Error(), configDirEnv) {
		t.Errorf("error should name the env var: %v", err)
	}
}

func TestLoadConfig_FailClosed_AbsentFile(t *testing.T) {
	dir := t.TempDir()
	getenv := func(k string) string {
		if k == configDirEnv {
			return dir
		}
		return ""
	}
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("expected fail-closed error for absent config file")
	}
}

func TestLoadConfig_FailClosed_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == configDirEnv {
			return dir
		}
		return ""
	}
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("expected fail-closed error for empty config file")
	}
}

func TestLoadConfig_FailClosed_Malformed(t *testing.T) {
	dir := t.TempDir()
	// Bytes that are not a valid protobuf wire encoding for EntrypointConfig.
	if err := os.WriteFile(filepath.Join(dir, configFileName), []byte{0xff, 0xff, 0xff, 0x0f}, 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == configDirEnv {
			return dir
		}
		return ""
	}
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("expected fail-closed error for malformed config")
	}
}

func TestValidate_FailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*runtimev1.EntrypointConfig)
		want   string
	}{
		{"no session uuid", func(p *runtimev1.EntrypointConfig) { p.SessionRef.SessionUuid = "" }, "session_uuid"},
		{"no command", func(p *runtimev1.EntrypointConfig) { p.Launch.Command = "" }, "launch.command"},
		{"no event socket", func(p *runtimev1.EntrypointConfig) { p.Attach.EventSocketPath = "" }, "event_socket_path"},
		{"relative event socket", func(p *runtimev1.EntrypointConfig) { p.Attach.EventSocketPath = "rel/sock" }, "must be absolute"},
		{"relative ca bundle", func(p *runtimev1.EntrypointConfig) { p.Egress.CaBundlePath = "rel/ca.pem" }, "must be absolute"},
		{"env without =", func(p *runtimev1.EntrypointConfig) { p.Launch.Env = []string{"BADENV"} }, "KEY=VALUE"},
		{"env with NUL", func(p *runtimev1.EntrypointConfig) { p.Launch.Env = []string{"K=v\x00x"} }, "NUL"},
		{"pem in ca path", func(p *runtimev1.EntrypointConfig) {
			p.Egress.CaBundlePath = "-----BEGIN CERTIFICATE-----abc"
		}, "credential material"},
		{"pem in token endpoint", func(p *runtimev1.EntrypointConfig) {
			p.SessionTokenEndpoint = "-----BEGIN PRIVATE KEY-----"
		}, "credential material"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pb := validProto()
			tc.mutate(pb)
			getenv := writeConfigDir(t, pb)
			_, err := loadConfig(getenv)
			if err == nil {
				t.Fatalf("expected validation error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v; want contains %q", err, tc.want)
			}
		})
	}
}

func TestFromProto_NilMessage(t *testing.T) {
	if _, err := fromProto(nil); err == nil {
		t.Fatal("expected error for nil proto")
	}
}

func TestFromProto_RoleOverlayOpaque(t *testing.T) {
	pb := validProto()
	pb.RoleOverlayRef = []byte{0x01, 0x02, 0x03}
	cfg, err := fromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	// The overlay is carried verbatim and never inspected.
	if len(cfg.roleOverlayRef) != 3 {
		t.Errorf("roleOverlayRef = %v; want 3 opaque bytes", cfg.roleOverlayRef)
	}
}
