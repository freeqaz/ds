// SPDX-License-Identifier: Apache-2.0
//
// ws.go — a minimal, stdlib-only RFC6455 WebSocket server endpoint.
//
// The client module is stdlib-only (client/go.mod, D80): no gorilla/websocket,
// no nhooyr. This is the small subset the demo needs — the server-side upgrade
// handshake and TEXT-frame read/write with client-masking — not a general
// implementation. It handles single-frame text messages (the demo's keystroke
// lines and JSON event broadcasts are small), responds to ping with pong and to
// close with close, and rejects anything it does not implement. It is demo-grade
// by charter; do not promote it to a transport.
package main

import (
	"bufio"
	"crypto/sha1" // #nosec G505 -- RFC 6455 mandates SHA-1 for the Sec-WebSocket-Accept handshake; not used as a security primitive.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// wsMagic is the RFC6455 GUID concatenated to Sec-WebSocket-Key for the accept.
const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsConn is a hijacked WebSocket connection. ReadText/WriteText carry a single
// UTF-8 text message each. It is NOT safe for concurrent writes — callers
// serialize writes themselves (the hub holds a per-conn write mutex).
type wsConn struct {
	rw      *bufio.ReadWriter
	closer  io.Closer
	wmu     sync.Mutex // guards frame writes (control + text may race)
	lastFin bool       // FIN bit of the most recent readFrame; consulted by ReadText for fragmentation
}

// wsUpgrade performs the server-side handshake and hijacks the connection. On
// failure it writes an HTTP error response and returns the error.
func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return nil, errors.New("not a websocket upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return nil, errors.New("response writer is not a Hijacker")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{rw: brw, closer: conn}, nil
}

func wsAcceptKey(key string) string {
	h := sha1.New() // #nosec G401 -- RFC 6455 Sec-WebSocket-Accept digest (SHA-1 + magic GUID), protocol-mandated, not a security primitive.
	h.Write([]byte(key + wsMagic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// ReadText reads frames until it returns a complete TEXT message (handling
// fragmentation), transparently answering ping with pong and close with close.
// It returns io.EOF (or another error) when the connection ends.
func (c *wsConn) ReadText() ([]byte, error) {
	var msg []byte
	expectingCont := false
	for {
		op, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch op {
		case opPing:
			if werr := c.writeFrame(opPong, payload); werr != nil {
				return nil, werr
			}
		case opPong:
			// ignore
		case opClose:
			_ = c.writeFrame(opClose, nil)
			return nil, io.EOF
		case opText:
			if expectingCont {
				return nil, errors.New("ws: text frame mid-fragment")
			}
			msg = append(msg, payload...)
			if c.lastFin {
				return msg, nil
			}
			expectingCont = true
		case opBinary:
			return nil, errors.New("ws: binary frames not supported")
		case opContinuation:
			if !expectingCont {
				return nil, errors.New("ws: unexpected continuation")
			}
			msg = append(msg, payload...)
			if c.lastFin {
				return msg, nil
			}
		default:
			return nil, fmt.Errorf("ws: unsupported opcode 0x%x", op)
		}
	}
}

// lastFin records the FIN bit of the most recent readFrame, consulted by
// ReadText to assemble fragmented messages.
//
// (Stored on the struct rather than returned to keep readFrame's signature small;
// readFrame is the only writer and ReadText the only reader, both single-thread
// on the read side.)

// WriteText sends p as a single unfragmented TEXT frame (server frames are
// unmasked per RFC6455). Safe to call from multiple goroutines (serialized).
func (c *wsConn) WriteText(p []byte) error { return c.writeFrame(opText, p) }

// Close best-effort sends a close frame and closes the underlying conn.
func (c *wsConn) Close() error {
	_ = c.writeFrame(opClose, nil)
	return c.closer.Close()
}

// --- framing -----------------------------------------------------------------

func (c *wsConn) readFrame() (opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(c.rw, hdr[:]); err != nil {
		return 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	c.lastFin = fin
	opcode = hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.rw, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.rw, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxWSFrame {
		return 0, nil, fmt.Errorf("ws: frame too large (%d bytes)", length)
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.rw, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(c.rw, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var hdr []byte
	b0 := byte(0x80) | opcode // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		hdr = []byte{b0, byte(n)}
	case n < 1<<16:
		hdr = []byte{b0, 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0] = b0
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	if _, err := c.rw.Write(hdr); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.rw.Write(payload); err != nil {
			return err
		}
	}
	return c.rw.Flush()
}

// maxWSFrame bounds one inbound frame — the demo's keystroke lines are tiny; this
// keeps a malformed/hostile length from allocating unbounded.
const maxWSFrame = 1 << 20
