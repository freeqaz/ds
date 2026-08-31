package tui

import (
	"bufio"
	"encoding/json"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// jsonDecoder builds the same decoder ndjsonStream uses, over a string of
// attach.v1 NDJSON — for tests that drive the stream one event at a time.
func jsonDecoder(s string) *json.Decoder {
	return json.NewDecoder(bufio.NewReader(strings.NewReader(s)))
}

// ev builds a minimal well-formed attach.Event with the given seq and type for
// the ordering tests. Only session.state is needed; it carries a payload so the
// envelope's exactly-one-payload contract holds.
func ev(seq uint64, typ attach.Type) attach.Event {
	e := attach.Event{Seq: seq, SessionID: "test-session", Type: typ}
	switch typ {
	case attach.TypeSessionState:
		e.SessionState = &attach.SessionState{State: attach.StateWorking}
	default:
		e.SessionState = &attach.SessionState{State: attach.StateWorking}
	}
	return e
}
