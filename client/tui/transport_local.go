package tui

import (
	"bufio"
	"encoding/json"
	"io"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// LocalTransport is the M0 direct leg (D79): the wrapper process emits
// attach.v1 events as NDJSON on a stream the client reads in-process. In a
// live attach this is the wrapper's stdout / a unix socket to the host agent;
// in replay it is a committed cassette golden. There is deliberately no remote
// dialing here — the WatchSession leg is a separate Transport (doc 15 §5.4).
//
// The writer leg is supplied by the caller (the live wrapper's stdin sink); in
// replay it is a no-op recorder so the ask-prompt flow is exercisable without
// a live runtime.
type LocalTransport struct {
	// Reader is the wrapper's attach-event NDJSON stream.
	Reader io.Reader
	// Sink receives writer-seat input; nil ⇒ a discard sink (reader-only or
	// replay). Only consulted when the handle carries RoleWriter.
	Sink WriterSink
}

// WriterSink is where the writer leg forwards input — the wrapper's stdin in a
// live attach. Splitting it out keeps the transport stream-direction agnostic
// and lets replay record decisions without a runtime.
type WriterSink interface {
	WriteInput(line string) error
	WriteAnswer(askID string, d Decision) error
}

// Open positions an ndjsonStream at the first event with Seq > fromSeq and
// returns a writer iff the handle is RoleWriter. The local leg orders by
// reading the pre-ordered wrapper stream; Seq is asserted monotonic by the
// model, not re-sorted here (the wrapper is the ordering authority, P10).
func (t *LocalTransport) Open(h AttachHandle, fromSeq uint64) (EventStream, Writer, error) {
	es := &ndjsonStream{
		dec:     json.NewDecoder(bufio.NewReader(t.Reader)),
		fromSeq: fromSeq,
	}
	if h.Role != RoleWriter {
		return es, nil, nil
	}
	sink := t.Sink
	if sink == nil {
		sink = discardSink{}
	}
	return es, &localWriter{sink: sink}, nil
}

// ndjsonStream decodes one attach.Event per line, skipping events at or below
// fromSeq so a re-attach resumes cleanly (the resume contract is per-event
// Seq, doc 15 §6.1 row 1).
type ndjsonStream struct {
	dec     *json.Decoder
	fromSeq uint64
}

func (s *ndjsonStream) Next() (attach.Event, error) {
	for {
		var ev attach.Event
		if err := s.dec.Decode(&ev); err != nil {
			return attach.Event{}, err // io.EOF at end, decode error otherwise
		}
		if ev.Seq <= s.fromSeq {
			continue // resume: already-rendered prefix
		}
		return ev, nil
	}
}

func (s *ndjsonStream) Close() error { return nil }

// localWriter forwards the writer-seat input legs to the sink. It stores no
// approval state (D45/D53): a Decision is forwarded, never persisted.
type localWriter struct {
	sink WriterSink
}

func (w *localWriter) SendInput(line string) error { return w.sink.WriteInput(line) }
func (w *localWriter) AnswerAsk(askID string, d Decision) error {
	return w.sink.WriteAnswer(askID, d)
}

// discardSink drops writer input — replay and reader-only modes. It explicitly
// does not record grants: there is no approval state anywhere client-side.
type discardSink struct{}

func (discardSink) WriteInput(string) error            { return nil }
func (discardSink) WriteAnswer(string, Decision) error { return nil }
