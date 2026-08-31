// SPDX-License-Identifier: Apache-2.0

package hostbridgewire

import (
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// srcLinksRepoRootPrefix is the fixed relative prefix from testdata/srclinks up to the
// repo root: srclinks → testdata → hostbridgewire → conformance-adapter → assurance →
// repo-root is five parents. Every link's target under SourceLinks is this prefix + its
// repo-relative source path, and this is the ONLY legitimate parent-relative string
// literal in the package (the guard trio's own expected link target).
const srcLinksRepoRootPrefix = "../../../../../"

// Source-of-truth files the pin reads, named by their testdata/srclinks symlink (see
// SourceLinks for the repo-relative targets — reading through the in-module link is
// what keeps Go's test cache honest). socket.go DEFINES the wire; wire.go HAND-MIRRORS
// the subset the orchestrator relay legs need — single-sourced there so pinning ONE
// file covers BOTH the write leg (drivesink_live.go) and the read leg
// (contentsource_live.go), which both speak it.
const (
	clientSocketSrc   = "client_hostbridge_socket"
	clientBridgeSrc   = "client_hostbridge_bridge"
	clientHandleSrc   = "client_hostbridge_handle"
	clientDriverSrc   = "client_claudecode_driver"
	orchWireSrc       = "orch_wire"
	goldenContractRel = "hostbridge_wire.golden.json"
)

// TestSourceLinksResolve guards the symlink farm itself: every registered link must
// BE a symlink whose target is exactly ../../../../../<repo-relative source>. A link
// replaced by a stale file COPY (which would freeze the pin against a dead snapshot)
// or retargeted at the wrong file turns the pin RED here.
func TestSourceLinksResolve(t *testing.T) {
	for link, target := range SourceLinks {
		path := filepath.Join("testdata", "srclinks", link)
		got, err := os.Readlink(path)
		if err != nil {
			t.Errorf("%s: not a symlink (a stale copy would freeze the pin): %v", path, err)
			continue
		}
		want := filepath.FromSlash(srcLinksRepoRootPrefix + target)
		if got != want {
			t.Errorf("%s -> %q; want %q", path, got, want)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: target unreadable: %v", path, err)
		}
	}
}

// TestSourceLinksCoverEveryCrossTreeRead pins that the srclink registry stays in
// lockstep with the readers: every reader-const naming a cross-tree source (the
// clientSocketSrc/…/orchWireSrc identifiers this package's pins anchor on) MUST name a
// registered SourceLinks entry, and every registered link MUST be named by a reader.
// A new cross-tree read added without a registered link — or a dead link no reader
// references — turns this RED, so the audit binds the mapping both ways (the coverage
// leg of the guard trio).
func TestSourceLinksCoverEveryCrossTreeRead(t *testing.T) {
	// The exact set of reader-const link names the package's pins read through
	// readTreeSource. Each MUST be a registered srclink.
	readerLinks := map[string]string{
		"clientSocketSrc": clientSocketSrc,
		"clientBridgeSrc": clientBridgeSrc,
		"clientHandleSrc": clientHandleSrc,
		"clientDriverSrc": clientDriverSrc,
		"orchWireSrc":     orchWireSrc,
	}
	used := make(map[string]bool, len(SourceLinks))
	for name, link := range readerLinks {
		if _, ok := SourceLinks[link]; !ok {
			t.Errorf("reader const %s = %q is not registered in SourceLinks — a cross-tree read that skips the tracked link defeats the test cache (register it under testdata/srclinks)", name, link)
			continue
		}
		used[link] = true
	}
	for link := range SourceLinks {
		if !used[link] {
			t.Errorf("SourceLinks entry %q is registered but no reader const references it (dead link — remove it or wire the reader)", link)
		}
	}
}

// TestNoRawParentDirStringLiterals is the REINTRODUCTION guard the registry tests above
// cannot provide: TestSourceLinksCoverEveryCrossTreeRead validates only the link names
// it already knows about, so a brand-new pin added with a raw "../../client/…" path (the
// exact test-cache hole this package's srclinks exist to close — cmd/go
// computeTestInputsID hashes only paths lexically inside the module root) would slip past
// it unseen. This test parses every .go file in the package and fails on ANY string
// LITERAL containing "../" — the only legitimate parent-relative literal is
// srcLinksRepoRootPrefix in THIS file (the guard's own expected link target). Comments
// mentioning ../../client/… in prose are untouched (the scan walks string literals, not
// source bytes). To add a new cross-tree read: add a tracked symlink under
// testdata/srclinks, register it in SourceLinks, and read it through readTreeSource.
func TestNoRawParentDirStringLiterals(t *testing.T) {
	// The needle is built by concatenation so this guard's own source never contains
	// the flagged substring as a single literal (each piece is inert on its own).
	rawParentDirNeedle := ".." + "/"
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir for the raw-read scan: %v (a read failure is a HARD failure — the scan must not vacuously pass)", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s for the raw-read scan: %v", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if !strings.Contains(val, rawParentDirNeedle) {
				return true
			}
			if name == "wire_test.go" && val == srcLinksRepoRootPrefix {
				return true // the guard's own expected-target prefix
			}
			t.Errorf("%s: string literal %q escapes the package via a parent-relative path — a raw cross-tree read defeats Go's test cache (warm-cache stale PASS); route it through a tracked testdata/srclinks link registered in SourceLinks and read it via readTreeSource", fset.Position(lit.Pos()), val)
			return true
		})
	}
}

// clientFrameNames maps client/hostbridge socket.go frameType const identifiers to
// the canonical golden frame names.
var clientFrameNames = map[string]string{
	"frameAttach": "attach", "frameAccept": "accept", "frameReject": "reject",
	"frameEvent": "event", "frameInput": "input", "frameGrant": "grant",
	"frameEnd": "end", "frameResume": "resume", "frameResumeReply": "resume_reply",
	"frameResumeReject": "resume_reject", "frameMode": "mode", "frameRawOut": "raw_out",
	"frameRawIn": "raw_in", "frameResize": "resize",
}

// clientRejectNames maps socket.go rejectCode const identifiers to canonical names.
var clientRejectNames = map[string]string{
	"rejectWriterSeatTaken": "writer_seat_taken", "rejectReaderCannotWr": "reader_cannot_write",
	"rejectAuthInvalid": "auth_invalid", "rejectHandleExpired": "handle_expired",
	"rejectHandleMalformed": "handle_malformed", "rejectUnknownSession": "unknown_session",
	"rejectInternal": "internal", "rejectTerminalReaderUnsupported": "terminal_reader_unsupported",
}

// clientResumeRejectNames maps socket.go resumeRejectCode const identifiers.
var clientResumeRejectNames = map[string]string{
	"resumeRejectWindowExceeded": "window_exceeded", "resumeRejectInternal": "internal",
}

// orchFrameNames maps wire.go bridgeFrameType const identifiers to the canonical
// golden frame names (the mirrored SUBSET both relay legs carry: the attach handshake,
// the write-leg input, the read-leg event, the terminal end, and the read-leg resume
// ring).
var orchFrameNames = map[string]string{
	"bridgeFrameAttach": "attach", "bridgeFrameAccept": "accept", "bridgeFrameReject": "reject",
	"bridgeFrameEvent": "event", "bridgeFrameInput": "input", "bridgeFrameEnd": "end",
	"bridgeFrameResume": "resume", "bridgeFrameResumeReply": "resume_reply",
	"bridgeFrameResumeReject": "resume_reject",
}

// orchRejectNames maps wire.go bridgeRejectCode const identifiers.
var orchRejectNames = map[string]string{
	"bridgeRejectWriterSeatTaken": "writer_seat_taken", "bridgeRejectAuthInvalid": "auth_invalid",
	"bridgeRejectHandleExpired": "handle_expired", "bridgeRejectHandleMalformed": "handle_malformed",
	"bridgeRejectUnknownSession": "unknown_session", "bridgeRejectInternal": "internal",
	"bridgeRejectTerminalReaderUnsupported": "terminal_reader_unsupported",
}

// orchResumeRejectNames maps wire.go bridgeResumeRejectCode const identifiers (the
// read-leg resume-ring refusal codes).
var orchResumeRejectNames = map[string]string{
	"bridgeResumeRejectWindowExceeded": "window_exceeded", "bridgeResumeRejectInternal": "internal",
}

func loadGolden(t *testing.T) GoldenContract {
	t.Helper()
	// The golden lives in this package's testdata; the test's working dir is the
	// package dir, so a relative testdata path resolves.
	b, err := os.ReadFile(filepath.Join("testdata", goldenContractRel))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g GoldenContract
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	return g
}

// canonicalize remaps a scraped name→value map (keyed by tree-specific const
// identifiers) into canonical-name→value, failing if an identifier is unknown.
func canonicalize(t *testing.T, tree string, scraped map[string]int, names map[string]string) map[string]int {
	t.Helper()
	out := make(map[string]int, len(scraped))
	for id, v := range scraped {
		canon, ok := names[id]
		if !ok {
			t.Errorf("%s: scraped const %q has no canonical mapping (a NEW wire const landed unmirrored — update the pin)", tree, id)
			continue
		}
		out[canon] = v
	}
	return out
}

// TestClientWireNumbersMatchGolden pins client/hostbridge/socket.go's ACTUAL frame,
// reject, and resume-reject numbers to the documented golden. A renumber in socket.go
// turns this RED.
func TestClientWireNumbersMatchGolden(t *testing.T) {
	g := loadGolden(t)
	src, err := readTreeSource(clientSocketSrc)
	if err != nil {
		t.Fatal(err)
	}

	frames := canonicalize(t, "client frames", scrapeByteConsts(src, "frameType"), clientFrameNames)
	assertNumbers(t, "client frames", frames, g.Frames, true)

	rejects := canonicalize(t, "client rejects", scrapeByteConsts(src, "rejectCode"), clientRejectNames)
	assertNumbers(t, "client rejects", rejects, g.RejectCodes, true)

	resumeRejects := canonicalize(t, "client resume-rejects", scrapeByteConsts(src, "resumeRejectCode"), clientResumeRejectNames)
	assertNumbers(t, "client resume-rejects", resumeRejects, g.ResumeRejectCodes, true)
}

// TestOrchestratorMirrorMatchesGolden pins the orchestrator relay legs' hand-mirrored
// bridge* numbers to the SAME golden. A renumber in wire.go turns this RED. The mirror
// is a subset (the legs name only the frames/codes they use), so this checks the
// mirrored names, not exhaustiveness — but it covers BOTH legs' surface (the shared
// wire.go), including the read-leg resume ring.
func TestOrchestratorMirrorMatchesGolden(t *testing.T) {
	g := loadGolden(t)
	src, err := readTreeSource(orchWireSrc)
	if err != nil {
		t.Fatal(err)
	}

	frames := canonicalize(t, "orch frames", scrapeByteConsts(src, "bridgeFrameType"), orchFrameNames)
	assertNumbers(t, "orch frames", frames, g.Frames, false)

	rejects := canonicalize(t, "orch rejects", scrapeByteConsts(src, "bridgeRejectCode"), orchRejectNames)
	assertNumbers(t, "orch rejects", rejects, g.RejectCodes, false)

	resumeRejects := canonicalize(t, "orch resume-rejects", scrapeByteConsts(src, "bridgeResumeRejectCode"), orchResumeRejectNames)
	assertNumbers(t, "orch resume-rejects", resumeRejects, g.ResumeRejectCodes, false)

	if len(frames) == 0 || len(rejects) == 0 || len(resumeRejects) == 0 {
		t.Fatal("orchestrator mirror scraped 0 constants — the pin is not reading wire.go (layout drift?)")
	}
}

// assertNumbers checks got (canonical name→value) against want. When exhaustive, got
// must cover every want key; otherwise got is a subset every element of which must
// match want.
func assertNumbers(t *testing.T, label string, got, want map[string]int, exhaustive bool) {
	t.Helper()
	if exhaustive {
		for name, w := range want {
			g, ok := got[name]
			if !ok {
				t.Errorf("%s: golden name %q absent from source (const renamed/removed?)", label, name)
				continue
			}
			if g != w {
				t.Errorf("%s: %q = %d; golden wants %d (WIRE DRIFT)", label, name, g, w)
			}
		}
		return
	}
	for name, g := range got {
		w, ok := want[name]
		if !ok {
			t.Errorf("%s: %q has no golden entry", label, name)
			continue
		}
		if g != w {
			t.Errorf("%s: %q = %d; golden wants %d (WIRE DRIFT)", label, name, g, w)
		}
	}
}

// TestMaxFrameBytesAgrees pins BOTH trees' single-frame payload cap to the golden
// expression. socket.go aliases it through maxLineBytes; wire.go inlines it.
func TestMaxFrameBytesAgrees(t *testing.T) {
	g := loadGolden(t)
	socket := mustRead(t, clientSocketSrc)
	bridge := mustRead(t, clientBridgeSrc)
	orch := mustRead(t, orchWireSrc)

	if !strings.Contains(socket, "maxFrameBytes = maxLineBytes") {
		t.Error("client socket.go: maxFrameBytes no longer aliases maxLineBytes (cap drift)")
	}
	if !strings.Contains(bridge, "maxLineBytes = "+g.MaxFrameBytesExpr) {
		t.Errorf("client bridge.go: maxLineBytes != %q (cap drift)", g.MaxFrameBytesExpr)
	}
	if !strings.Contains(orch, "bridgeMaxFrameBytes = "+g.MaxFrameBytesExpr) {
		t.Errorf("orchestrator wire.go: bridgeMaxFrameBytes != %q (cap drift)", g.MaxFrameBytesExpr)
	}
}

// TestWireStringsAgree pins the transport + role wire strings on both sides. wire.go
// carries BOTH roles (the write leg WRITER + the read leg READER), so both are pinned.
func TestWireStringsAgree(t *testing.T) {
	g := loadGolden(t)
	socket := mustRead(t, clientSocketSrc)
	handle := mustRead(t, clientHandleSrc)
	orch := mustRead(t, orchWireSrc)

	// client: TransportUnix + RoleWriter/RoleReader are declared in socket.go/handle.go.
	assertContains(t, "client socket.go", socket, `EndpointTransport = "`+g.TransportUnix+`"`)
	assertContains(t, "client handle.go", handle, `RoleWriter Role = "`+g.RoleWriter+`"`)
	assertContains(t, "client handle.go", handle, `RoleReader Role = "`+g.RoleReader+`"`)
	// orchestrator mirror (both legs' shared wire.go).
	assertContains(t, "orch wire.go", orch, `bridgeTransportUnix = "`+g.TransportUnix+`"`)
	assertContains(t, "orch wire.go", orch, `bridgeRoleWriter = "`+g.RoleWriter+`"`)
	assertContains(t, "orch wire.go", orch, `bridgeRoleReader = "`+g.RoleReader+`"`)
}

// TestHandleJSONTagsAgree pins the attach-handshake JSON field tags on BOTH sides.
// A tag rename on either tree silently breaks the live attach decode; here it is RED.
func TestHandleJSONTagsAgree(t *testing.T) {
	g := loadGolden(t)
	handle := mustRead(t, clientHandleSrc)
	driver := mustRead(t, clientDriverSrc)
	orch := mustRead(t, orchWireSrc)

	for _, tag := range g.HandleJSONTags {
		lit := `json:"` + tag + `"`
		assertContains(t, "client handle.go", handle, lit)
		assertContains(t, "orch wire.go", orch, lit)
	}
	textLit := `json:"` + g.DriveInputTextTag + `"`
	assertContains(t, "client driver.go (DriveInput)", driver, textLit)
	assertContains(t, "orch wire.go (wireDriveInput)", orch, textLit)
}

// TestGoldenFrameBytes pins the exact on-wire byte layout (type byte + 4-byte BE length
// + payload) of representative frames against the checked-in golden hex. A framing OR a
// frame-number change shifts these bytes.
func TestGoldenFrameBytes(t *testing.T) {
	g := loadGolden(t)

	inputFrame := FrameBytes(byte(g.Frames["input"]), []byte(`{"text":"hi"}`))
	assertHexEqual(t, "input_text_hi", inputFrame, g.GoldenFramesHex["input_text_hi"])

	rejectFrame := FrameBytes(byte(g.Frames["reject"]), []byte{byte(g.RejectCodes["writer_seat_taken"])})
	assertHexEqual(t, "reject_writer_seat_taken", rejectFrame, g.GoldenFramesHex["reject_writer_seat_taken"])
}

func assertHexEqual(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	if wantHex == "" {
		t.Fatalf("golden hex for %q is empty", name)
	}
	if h := hex.EncodeToString(got); h != wantHex {
		t.Fatalf("frame %q bytes = %s; golden wants %s (wire framing/number drift)", name, h, wantHex)
	}
}

func mustRead(t *testing.T, rel string) string {
	t.Helper()
	s, err := readTreeSource(rel)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func assertContains(t *testing.T, where, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("%s: missing %q (wire drift or the pin is stale)", where, needle)
	}
}
