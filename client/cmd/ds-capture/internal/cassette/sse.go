// SPDX-License-Identifier: Apache-2.0

package cassette

import (
	"bufio"
	"strings"
)

// SSEEvent is one parsed Server-Sent Event: its event: name (if any) and the
// concatenated data: payload. Per the CAPTURE-TOOL-DESIGN.md §2 cut-list we
// KEEP the event:/data: framing parse and DROP the latency/thinking metrics
// surface (TTFB/TTFT, cache-token rollups) cia's SSEParser computed — those are
// `cia report` analytics, out of this tool's charter. This is purely a
// structural summary used by inspect (and to sanity-tee a recorded body).
type SSEEvent struct {
	Event string
	Data  string
}

// ParseSSE splits a decoded SSE stream into its events. The stream is
// line-oriented text: `event: <name>` and `data: <payload>` lines, with a
// blank line terminating each event (per the SSE spec and Anthropic's
// /v1/messages stream). Multiple data: lines within one event are joined with
// "\n", as the SSE spec prescribes. Because record strips Accept-Encoding the
// body arrives plaintext, so a bufio.Scanner over the text suffices.
func ParseSSE(body string) []SSEEvent {
	var events []SSEEvent
	sc := bufio.NewScanner(strings.NewReader(body))
	// Allow long data: lines (a single SSE event can carry a large JSON delta).
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var curEvent string
	var dataLines []string
	haveData := false

	flush := func() {
		if !haveData && curEvent == "" {
			return
		}
		events = append(events, SSEEvent{
			Event: curEvent,
			Data:  strings.Join(dataLines, "\n"),
		})
		curEvent = ""
		dataLines = nil
		haveData = false
	}

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			// Blank line: dispatch the accumulated event.
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			// SSE comment line — ignored.
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			// A field name with no colon is the whole field, empty value.
			field = line
			value = ""
		}
		// Per spec a single leading space after the colon is stripped.
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			curEvent = value
		case "data":
			dataLines = append(dataLines, value)
			haveData = true
		default:
			// id:, retry:, and unknown fields are not needed for the cassette
			// summary — dropped (no metrics surface per the cut-list).
		}
	}
	// Dispatch a trailing event that wasn't followed by a blank line.
	flush()
	return events
}

// EventTypes returns the ordered list of event: names in an SSE body — the
// thin slice inspect prints to summarize an interaction without parsing the
// JSON deltas.
func EventTypes(body string) []string {
	evs := ParseSSE(body)
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		if e.Event != "" {
			out = append(out, e.Event)
		}
	}
	return out
}
