package tui

import (
	"errors"
	"io"
)

// replay.go drives a committed attach.v1 NDJSON stream (a goldentrace replay
// golden) through the same Transport -> Model -> render path a live attach
// uses. It is the deterministic surface the render tests and the binary's
// replay mode share, so "renders correctly in replay" and "renders correctly
// live" exercise one code path (only the Transport differs).

// BuildModel folds an attach.v1 NDJSON stream into a Model via the local
// transport, resuming at fromSeq+1. It is the model half of replay, separated
// so tests can assert on the structured Model (asks, park state, tree) without
// touching the rendered bytes. role selects writer vs reader; replay uses a
// discard sink, so a RoleWriter handle exercises the ask-answer path without a
// live runtime.
func BuildModel(r io.Reader, role Role, fromSeq uint64) (*Model, Writer, error) {
	tr := &LocalTransport{Reader: r}
	handle := AttachHandle{
		SessionUUID: "",
		Endpoints:   []EndpointCandidate{{Kind: "local", Address: "replay"}},
		Role:        role,
	}
	stream, writer, err := tr.Open(handle, fromSeq)
	if err != nil {
		return nil, nil, err
	}
	defer stream.Close()

	m := NewModel()
	for {
		ev, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if err := m.Apply(ev); err != nil {
			return nil, nil, err
		}
	}
	return m, writer, nil
}

// Replay folds an attach.v1 NDJSON stream into a Model and writes the plain
// (golden) render to w. This is the binary's replay mode and the render-test
// helper in one call.
func Replay(r io.Reader, w io.Writer) (*Model, error) {
	m, _, err := BuildModel(r, RoleReader, 0)
	if err != nil {
		return nil, err
	}
	if err := RenderPlain(w, m); err != nil {
		return nil, err
	}
	return m, nil
}
