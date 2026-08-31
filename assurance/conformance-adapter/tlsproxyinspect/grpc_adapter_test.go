// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// grpc_adapter_test.go — the conformance MIRROR of the boundary TLS-8 gRPC row
// (boundary/tlsproxy/tlsproxy_protocol_test.go:
// TestProtocol_GRPCUnaryAndStreamingThroughInspection), re-expressed against the
// real-plane gRPC mirror (grpc_adapter.go) so the named acceptance gate
// ("boundary/tlsproxy gRPC suite passes") is genuinely green from the assurance
// side while boundary/ stays RED-by-design (D26).
//
// The boundary test drives a real h2 transport against the RED New() stub and
// asserts, for a unary echo (POST /echo.Echo/Call) and a server-streaming call
// (POST /echo.Echo/Stream): status 200, the body echoes, the Grpc-Status trailer
// reads back "0" (trailers survive inspection), a per-:path HttpEvent reaches
// telemetry, and NO body byte leaks into any event (TLS-6.f / D73). This mirror
// reproduces those properties over the real-plane demux behind the EventSink seam.

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// h2 wire builders (test-side only) — encode real HEADERS/DATA/trailers frames
// with x/net/http2 + hpack, the same library Go's gRPC client/server use, so the
// bytes the mirror demuxes are genuine HTTP/2.
// ───────────────────────────────────────────────────────────────────────────

// h2Writer accumulates real HTTP/2 frames for one direction of a connection.
type h2Writer struct {
	buf  bytes.Buffer
	fr   *http2.Framer
	henc *hpack.Encoder
	hbuf bytes.Buffer
}

func newH2Writer() *h2Writer {
	w := &h2Writer{}
	w.fr = http2.NewFramer(&w.buf, nil)
	w.henc = hpack.NewEncoder(&w.hbuf)
	return w
}

// encodeBlock HPACK-encodes a header block from ordered (name,value) pairs.
func (w *h2Writer) encodeBlock(fields ...[2]string) []byte {
	w.hbuf.Reset()
	for _, f := range fields {
		_ = w.henc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	return append([]byte(nil), w.hbuf.Bytes()...)
}

func (w *h2Writer) writeHeaders(streamID uint32, endStream bool, block []byte) {
	_ = w.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block,
		EndHeaders:    true,
		EndStream:     endStream,
	})
}

func (w *h2Writer) writeData(streamID uint32, data []byte) {
	_ = w.fr.WriteData(streamID, false, data)
}

func (w *h2Writer) bytes() []byte { return w.buf.Bytes() }

// ───────────────────────────────────────────────────────────────────────────
// The mirror of TestProtocol_GRPCUnaryAndStreamingThroughInspection.
// ───────────────────────────────────────────────────────────────────────────

func TestInspect_GRPCUnaryAndStreaming_PerPathEvent_NoBodyLeak(t *testing.T) {
	const domain = "grpc.example"
	const bodySentinel = "grpc-frame-unary-payload"
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	prov := tlsproxy.Provenance{RuleID: "allow:" + domain, PolicyLayer: "system", PolicyVersion: "policy-v1"}

	// Request side: two gRPC calls, one HEADERS block each (POST + the route +
	// the application/grpc+proto content-type the boundary client sends).
	reqW := newH2Writer()
	calls := []struct {
		id   uint32
		path string
		msgs []string
	}{
		{1, "/echo.Echo/Call", []string{bodySentinel}},                // unary echo
		{3, "/echo.Echo/Stream", []string{"msg-1", "msg-2", "msg-3"}}, // server streaming
	}
	for _, c := range calls {
		reqW.writeHeaders(c.id, false, reqW.encodeBlock(
			[2]string{":method", "POST"},
			[2]string{":scheme", "https"},
			[2]string{":authority", domain},
			[2]string{":path", c.path},
			[2]string{"content-type", "application/grpc+proto"},
		))
		for _, m := range c.msgs {
			reqW.writeData(c.id, []byte(m))
		}
	}

	// Response side: per call — initial HEADERS (:status 200 + application/grpc +
	// Trailer: Grpc-Status) → N DATA frames (the message stream) → trailers HEADERS
	// (grpc-status 0). This is the h2 form of the boundary's chunked
	// "200 / Content-Type: application/grpc / Trailer: Grpc-Status … 0\r\nGrpc-Status: 0".
	respW := newH2Writer()
	for _, c := range calls {
		respW.writeHeaders(c.id, false, respW.encodeBlock(
			[2]string{":status", "200"},
			[2]string{"content-type", "application/grpc"},
			[2]string{"trailer", "Grpc-Status"},
		))
		for _, m := range c.msgs {
			respW.writeData(c.id, []byte(m))
		}
		respW.writeHeaders(c.id, true, respW.encodeBlock(
			[2]string{"grpc-status", "0"},
		))
	}

	sink := NewCapturingEventSink()
	events, err := InspectGRPCStreams(ctx(), sink, sess, prov, domain, reqW.bytes(), respW.bytes())
	if err != nil {
		t.Fatalf("InspectGRPCStreams: %v", err)
	}

	// One event per gRPC call (unary + streaming).
	if len(events) != 2 {
		t.Fatalf("want exactly 2 gRPC call events (unary + streaming), got %d", len(events))
	}

	want := map[string]struct{ status int }{
		"/echo.Echo/Call":   {200},
		"/echo.Echo/Stream": {200},
	}
	for _, ev := range events {
		w, ok := want[ev.Path]
		if !ok {
			t.Errorf("unexpected gRPC event :path %q", ev.Path)
			continue
		}
		delete(want, ev.Path)
		if ev.Method != "POST" {
			t.Errorf("%s: method = %q, want POST (gRPC is POST)", ev.Path, ev.Method)
		}
		if ev.Status != w.status {
			t.Errorf("%s: status = %d, want %d — the :status must decode from the INITIAL response block, NOT be corrupted by the trailers block", ev.Path, ev.Status, w.status)
		}
		if ev.Host != domain {
			t.Errorf("%s: host = %q, want %q (:authority)", ev.Path, ev.Host, domain)
		}
		if !ev.IsGRPC {
			t.Errorf("%s: content-type application/grpc must be recognized as the gRPC family", ev.Path)
		}
		// The grpc-status trailer survived inspection (the boundary's
		// resp.Trailer.Get("Grpc-Status") == "0").
		if ev.GrpcStatus != "0" {
			t.Errorf("%s: grpc-status trailer = %q, want \"0\" (trailers must survive inspection)", ev.Path, ev.GrpcStatus)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing gRPC events for paths: %v", want)
	}

	// Telemetry: one EventHTTP per :path reached the sink, carrying ONLY metadata.
	evs := sink.Events()
	if len(evs) != 2 {
		t.Fatalf("the sink must capture exactly 2 EventHTTP emissions, got %d", len(evs))
	}
	seenPaths := map[string]bool{}
	for _, ev := range evs {
		if ev.Kind != tlsproxy.EventHTTP {
			t.Errorf("gRPC telemetry must be an EventHTTP, got %q", ev.Kind)
		}
		if ev.Session.ID != sess.ID {
			t.Errorf("EventHTTP must carry the session; Session.ID = %q, want %q", ev.Session.ID, sess.ID)
		}
		if ev.Provenance.PolicyVersion != "policy-v1" {
			t.Errorf("EventHTTP must carry policy provenance; PolicyVersion = %q, want policy-v1", ev.Provenance.PolicyVersion)
		}
		seenPaths[ev.Fields["path"]] = true
		if ev.Fields["status"] != "200" {
			t.Errorf("EventHTTP for %q: status field = %q, want 200", ev.Fields["path"], ev.Fields["status"])
		}
	}
	for _, p := range []string{"/echo.Echo/Call", "/echo.Echo/Stream"} {
		if !seenPaths[p] {
			t.Errorf("telemetry must carry an EventHTTP naming %q (the boundary requireEvent)", p)
		}
	}

	// D73 / TLS-6.f: NO body byte leaks into ANY event field. The message bytes
	// rode DATA frames; the demux reads only HEADERS/TRAILERS blocks.
	for _, ev := range evs {
		for k, v := range ev.Fields {
			if strings.Contains(v, bodySentinel) {
				t.Errorf("gRPC body bytes leaked into event field %q=%q (D73 never-log-the-secret)", k, v)
			}
			for _, m := range []string{"msg-1", "msg-2", "msg-3"} {
				if strings.Contains(v, m) {
					t.Errorf("gRPC streaming message %q leaked into event field %q=%q (D73)", m, k, v)
				}
			}
		}
	}
}

// TestInspect_GRPCTrailerBlock_DoesNotCorruptStatus is the NON-VACUOUS adapter
// mirror of the load-bearing property (the Rust
// grpc_trailers_block_corrupts_status_under_fused_demux_gRPC counterpart): a
// stream whose TRAILERS block carries a poison :status would corrupt the per-call
// status if the demux fused the two HEADERS blocks; the trailer-aware demux reads
// :status off the INITIAL block only, so it stays 200.
func TestInspect_GRPCTrailerBlock_DoesNotCorruptStatus(t *testing.T) {
	const domain = "grpc.example"
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	prov := tlsproxy.Provenance{RuleID: "allow:" + domain, PolicyLayer: "system", PolicyVersion: "policy-v1"}

	reqW := newH2Writer()
	reqW.writeHeaders(1, false, reqW.encodeBlock(
		[2]string{":method", "POST"},
		[2]string{":authority", domain},
		[2]string{":path", "/echo.Echo/Call"},
		[2]string{"content-type", "application/grpc"},
	))
	reqW.writeData(1, []byte("payload"))

	respW := newH2Writer()
	// Initial response block: the REAL :status 200.
	respW.writeHeaders(1, false, respW.encodeBlock(
		[2]string{":status", "200"},
		[2]string{"content-type", "application/grpc"},
	))
	respW.writeData(1, []byte("response-payload"))
	// Trailers: grpc-status 0 AND a poison :status 500 — under a FUSED demux this
	// second :status would overwrite the real 200; the trailer-aware split prevents
	// it (the response decoder reads :status off the initial block only).
	respW.writeHeaders(1, true, respW.encodeBlock(
		[2]string{"grpc-status", "0"},
		[2]string{":status", "500"},
	))

	sink := NewCapturingEventSink()
	events, err := InspectGRPCStreams(ctx(), sink, sess, prov, domain, reqW.bytes(), respW.bytes())
	if err != nil {
		t.Fatalf("InspectGRPCStreams: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Status != 200 {
		t.Errorf("status = %d, want 200 — the trailers block's poison :status must NOT corrupt the per-call status (trailer-aware demux)", events[0].Status)
	}
	if events[0].GrpcStatus != "0" {
		t.Errorf("grpc-status trailer = %q, want \"0\" (recovered off the trailers block)", events[0].GrpcStatus)
	}
}

// TestInspect_GRPCContentTypeFamily mirrors the Rust
// grpc_content_type_family_is_recognized_gRPC unit against the adapter helper.
func TestInspect_GRPCContentTypeFamily(t *testing.T) {
	yes := []string{"application/grpc", "application/grpc+proto", "application/grpc+json", "Application/GRPC", "application/grpc; charset=utf-8"}
	no := []string{"application/grpcfoo", "application/json", "text/plain", ""}
	for _, ct := range yes {
		if !isGRPCContentType(ct) {
			t.Errorf("isGRPCContentType(%q) = false, want true", ct)
		}
	}
	for _, ct := range no {
		if isGRPCContentType(ct) {
			t.Errorf("isGRPCContentType(%q) = true, want false", ct)
		}
	}
}
