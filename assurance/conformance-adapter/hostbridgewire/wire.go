// SPDX-License-Identifier: Apache-2.0

package hostbridgewire

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
)

// GoldenContract is the documented single source of the host-agent bridge wire
// numbers both trees mirror. It is loaded from testdata/hostbridge_wire.golden.json
// and asserted against each tree's scraped source.
type GoldenContract struct {
	// Frames maps a canonical frame name (attach, input, ...) to its 1-byte type.
	Frames map[string]int `json:"frames"`
	// RejectCodes maps a canonical reject-cause name to its 1-byte wire code.
	RejectCodes map[string]int `json:"reject_codes"`
	// ResumeRejectCodes maps a canonical resume-reject name to its 1-byte code.
	ResumeRejectCodes map[string]int `json:"resume_reject_codes"`
	// MaxFrameBytesExpr is the Go expression BOTH trees' payload cap must be (the
	// exact source text, e.g. "10 << 20"), pinned as text because the client side
	// aliases it through a named const.
	MaxFrameBytesExpr string `json:"max_frame_bytes_expr"`
	// RoleWriter / RoleReader / TransportUnix are the wire string constants.
	RoleWriter    string `json:"role_writer"`
	RoleReader    string `json:"role_reader"`
	TransportUnix string `json:"transport_unix"`
	// HandleJSONTags is the set of JSON field tags the attach-handshake shapes carry
	// on the wire; both trees' handle/endpoint/auth structs must tag with these.
	HandleJSONTags []string `json:"handle_json_tags"`
	// DriveInputTextTag is the JSON tag of the single text body a DriveInput frame
	// carries ({"text": ...}).
	DriveInputTextTag string `json:"drive_input_text_tag"`
	// GoldenFramesHex is a set of representative frames rendered to hex (type byte +
	// 4-byte BE length + payload) — the on-wire byte layout pin.
	GoldenFramesHex map[string]string `json:"golden_frames_hex"`
}

// FrameBytes renders one type-length-payload wire frame exactly as BOTH trees'
// writeFrame (client/hostbridge) / writeBridgeFrame (orchestrator) emit: a single
// type byte, a 4-byte BIG-ENDIAN payload length, then the payload. It is the byte
// layout the golden hex vectors encode.
func FrameBytes(frameType byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = frameType
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// SourceLinks maps each tracked symlink under testdata/srclinks (the ONLY path the
// pin reads a sibling tree's source through) to the repo-relative file it must point
// at. TestSourceLinksResolve guards the mapping, so a link silently replaced by a
// stale COPY (which would freeze the pin against a dead snapshot) turns the pin RED.
var SourceLinks = map[string]string{
	"client_hostbridge_socket": "client/hostbridge/socket.go",
	"client_hostbridge_bridge": "client/hostbridge/bridge.go",
	"client_hostbridge_handle": "client/hostbridge/handle.go",
	"client_claudecode_driver": "client/wrapper/adapters/claude-code/driver.go",
	// The orchestrator single-sources BOTH relay legs' mirrored bridge wire (the frame codec,
	// attach handle, reject map, and frame/role/tag space) in wire.go — the WRITE leg
	// (drivesink_live.go) and the READ leg (contentsource_live.go) both speak it. Pinning this
	// ONE file covers both legs' full wire surface: a renumber/tag-rename on either leg is RED.
	"orch_wire": "orchestrator/cmd/orchestrator/wire.go",
}

// srcLinksDir is the in-module directory holding the cross-tree source symlinks,
// relative to this package's directory.
const srcLinksDir = "testdata/srclinks"

// pkgDir returns this package's directory via THIS source file's compiled-in path,
// so the pin resolves testdata regardless of the test's working directory.
func pkgDir() (string, error) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("hostbridgewire: cannot resolve own source path")
	}
	return filepath.Dir(self), nil
}

// readTreeSource reads a sibling tree's source file THROUGH its symlink under
// testdata/srclinks — never via the repo root directly. This is load-bearing for
// correctness of the pin under Go's TEST CACHE: cmd/go's computeTestInputsID hashes
// only files opened at paths lexically inside this module's root ("Do not recheck
// files outside the module"), so a direct ../../client/... read would let a warm
// cache serve a stale PASS after a cross-tree renumber. Opening the in-module link
// path IS tracked, and os.Stat/os.ReadFile FOLLOW the link, so the tracked hash pins
// the real file's size+mtime and the pin re-runs the moment either tree changes.
func readTreeSource(linkName string) (string, error) {
	if _, ok := SourceLinks[linkName]; !ok {
		return "", fmt.Errorf("hostbridgewire: %q is not a registered source link", linkName)
	}
	dir, err := pkgDir()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(srcLinksDir), linkName))
	if err != nil {
		return "", fmt.Errorf("hostbridgewire: read %s (-> %s): %w", linkName, SourceLinks[linkName], err)
	}
	return string(b), nil
}

// scrapeByteConsts extracts `<name> <typeName> = <int>` const declarations from Go
// source, returning name→value. It is how the pin reads each tree's ACTUAL wire
// numbers (not a second hand-copied literal), so a renumber in the source is seen.
func scrapeByteConsts(src, typeName string) map[string]int {
	re := regexp.MustCompile(`(?m)^\s*(\w+)\s+` + regexp.QuoteMeta(typeName) + `\s*=\s*(\d+)\b`)
	out := make(map[string]int)
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		v, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		out[m[1]] = v
	}
	return out
}
