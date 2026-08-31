// SPDX-License-Identifier: Apache-2.0
//
// fakecc.go — the offline echo-CC stand-in (the Tier-1, zero-spend demo brain).
//
// It is an in-process io.Reader/io.Writer pair that mimics just enough of the
// `claude --print --output-format stream-json` wire for the Bridge's adapter to
// project chat.message events: it reads the driver-encoded user-input records the
// Bridge writes onto its "stdin" (one JSON record per line, {type:"user",
// message:{role,content:[{type:"text",text}]}}) and, per record, emits a
// stream-json assistant line whose text echoes the input. No network, no API
// spend — the always-green stand-in for a real CC. NOT a fixture (those are
// re-authored synthetic captures owned elsewhere); this is a live echo.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

// launchFakeCC builds an echo CC wired to a Bridge: input records the Bridge
// writes are echoed back as assistant chat.message lines on the Bridge's pump
// input. It runs entirely in-process; cleanup closes the input side.
func launchFakeCC() *ccProcess {
	in := newEchoCC()
	// The Bridge writes driver records to `in` (CC stdin) and Pumps from
	// `in.stdout` (CC stdout). NewBridge over in as the stdin sink.
	b := hostbridge.NewBridge(in, hostbridge.BridgeConfig{})
	cleanup := func() { in.Close() }
	return &ccProcess{bridge: b, stdout: in.stdout, cleanup: cleanup}
}

// echoCC is the in-process fake CC. The Bridge's writes (Write) are parsed as
// user-input records; each yields one assistant stream-json line written to the
// stdout pipe that the Bridge's Pump reads.
type echoCC struct {
	pw      *io.PipeWriter // CC stdout write side (echoCC -> Bridge.Pump)
	stdout  *io.PipeReader // CC stdout read side
	pending chan string    // input texts awaiting an echo
	buf     []byte         // accumulates partial records across Writes
	closed  atomic.Bool

	// raw records every byte the Bridge wrote to CC stdin, so the test can prove
	// byte-atomic fan-in (each newline-framed frame parses as one whole record).
	rawMu sync.Mutex
	raw   bytes.Buffer
}

func newEchoCC() *echoCC {
	pr, pw := io.Pipe()
	e := &echoCC{pw: pw, stdout: pr, pending: make(chan string, 1024)}
	go e.loop()
	return e
}

// Write receives a driver-encoded user-input record (one per newline-framed
// call; the Bridge frames each record with a trailing '\n'). It parses the text
// and queues an echo. It implements io.Writer so it is the Bridge's ccStdin.
func (e *echoCC) Write(p []byte) (int, error) {
	if e.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	e.rawMu.Lock()
	e.raw.Write(p)
	e.rawMu.Unlock()
	// The Bridge writes a record then a separate '\n'. Buffer and split on
	// newlines so a record split across two Writes still parses.
	e.buf = append(e.buf, p...)
	for {
		i := indexByte(e.buf, '\n')
		if i < 0 {
			break
		}
		line := e.buf[:i]
		e.buf = e.buf[i+1:]
		text := parseUserText(line)
		if text != "" {
			// Block on a full queue (back-pressure) rather than drop — the loop
			// goroutine drains it. The Bridge serializes writes under stdinMu, so a
			// brief block here only paces the shared keyboard, never tears a record.
			e.pending <- text
		}
	}
	return len(p), nil
}

// Close is invoked by the Bridge (ccStdin is an io.Closer): it closes the
// stdout pipe so Pump sees EOF.
func (e *echoCC) Close() error {
	if e.closed.Swap(true) {
		return nil
	}
	close(e.pending)
	return nil
}

// rawWritten returns a copy of every byte the Bridge wrote to CC stdin — the
// shared-stdin wire, for the test's byte-atomic fan-in assertion.
func (e *echoCC) rawWritten() []byte {
	e.rawMu.Lock()
	defer e.rawMu.Unlock()
	return append([]byte(nil), e.raw.Bytes()...)
}

// loop turns queued input texts into assistant stream-json lines on the stdout
// pipe. One line per input; when pending closes, EOF the stdout pipe.
func (e *echoCC) loop() {
	seq := 0
	for text := range e.pending {
		seq++
		line := assistantLine(seq, "echo: "+text)
		if _, err := e.pw.Write(append(line, '\n')); err != nil {
			break
		}
	}
	_ = e.pw.Close()
}

// --- stream-json synthesis ---------------------------------------------------

// assistantLine renders a minimal `assistant` stream-json line the adapter
// projects into a chat.message with a single text block.
func assistantLine(seq int, text string) []byte {
	rec := map[string]any{
		"type":               "assistant",
		"session_id":         "00000000-0000-4000-8000-000000000fed",
		"uuid":               fmt.Sprintf("00000000-0000-4000-8000-%012d", seq),
		"parent_tool_use_id": nil,
		"request_id":         fmt.Sprintf("req_echo_%04d", seq),
		"message": map[string]any{
			"id":      fmt.Sprintf("msg_echo_%04d", seq),
			"type":    "message",
			"role":    "assistant",
			"model":   "fake-echo",
			"content": []map[string]any{{"type": "text", "text": text}},
		},
	}
	b, _ := json.Marshal(rec)
	return b
}

// parseUserText extracts the text block from a driver-encoded user-input record
// ({type:"user", message:{role:"user", content:[{type:"text", text}]}}). Returns
// "" if the line is not such a record.
func parseUserText(line []byte) string {
	var rec struct {
		Type    string `json:"type"`
		Message struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"message"`
	}
	if json.Unmarshal(line, &rec) != nil || rec.Type != "user" {
		return ""
	}
	for _, c := range rec.Message.Content {
		if c.Type == "text" && c.Text != "" {
			return c.Text
		}
	}
	return ""
}

// indexByte is bytes.IndexByte without importing bytes (kept local to the file's
// tiny surface).
func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
