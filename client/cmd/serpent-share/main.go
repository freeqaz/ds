// SPDX-License-Identifier: Apache-2.0
//
// Command serpent-share is a DEMO-GRADE tmux-style 2-person shared Claude Code
// session: N browser clients connect over WebSocket to ONE shared CC stdin (the
// shared keyboard — every client's keystrokes land on the same process input)
// and EVERY client receives the same broadcast of CC's projected output stream.
//
//	serpent-share                       # launch real local CC (egress via ds-capture), serve on a free port
//	serpent-share --addr 127.0.0.1:8099 # pin the WS/HTTP listen address
//	serpent-share --fake                # offline demo: an echo CC stand-in, no API spend
//
// WHY THE BRIDGE DIRECTLY (Substrate A, D141). hostbridge.Bridge is ALREADY the
// shared-stdio engine this demo needs:
//
//   - Pump(ctx, ccStdout) fans every projected attach.Event to EVERY Subscribe()r
//     (fan-out) — so each browser registers a per-connection Subscriber and gets
//     the full broadcast;
//   - DriveInput(DriveInput{Text}) serializes ANY caller's write onto CC stdin
//     under stdinMu (byte-atomic fan-in) — so every browser's input call lands on
//     the same shared stdin, whole-record-at-a-time, never torn mid-record.
//
// This deliberately BYPASSES hostbridge.Server, whose Attach enforces the D61
// one-writer/N-reader seat — the exact OPPOSITE of D141's shared keyboard. The
// Server/WriterRelay seat-arbitration invariants are untouched: this command
// imports the Bridge, not the Server, and is a DEMO, not the productized path.
//
// D141: imperfect interleaving is FINE; the rigorous turn-serializer is DEFERRED.
// Two authors' lines can interleave into one CC turn and produce a garbled turn —
// that is the accepted-imperfect part. We mitigate cosmetically (per-author text
// tags + line-boundary flushing) and document it loudly in the README; we do NOT
// serialize turns.
//
// OSS (D15/D25): open client tooling, stdlib-only (client/go.mod). Egress flows
// through the first-party ds-capture gateway (never the protected :18080
// monitor). The gateway cassette + any raw CC capture are raw-class (D50): they
// stay under ~/tmp/ and are reaped on exit.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

const protectedMonitorPort = 18080

//go:embed web/index.html
var webFS embed.FS

const rootUsage = `serpent-share — DEMO: a tmux-style 2-person shared Claude Code session

usage: serpent-share [flags]

N browser clients connect over WebSocket; EVERY client's keystrokes land on ONE
shared Claude Code stdin (the shared keyboard) and EVERY client receives the same
broadcast of CC's output stream. Imperfect interleaving is ACCEPTED (D141): two
authors' lines may interleave into one CC turn. Input is tagged per client.

This BYPASSES the Server one-writer/N-reader seat ON PURPOSE — it is a demo of
shared stdin (D141), NOT the productized WriterRelay path. See README.md.

flags:
  --addr HOST:PORT   listen address for the demo HTTP/WS server (default 127.0.0.1:<free port>)
  --claude PATH      claude binary (default $CLAUDE_BIN, then 'claude' on PATH)
  --capture-bin PATH ds-capture binary (default $DS_CAPTURE_BIN, then PATH, then sibling)
  --port N           ds-capture egress-gateway port (0 = auto; never :18080)
  --scratch DIR      job dir for the gateway CA + cassette (default a temp dir under ~/tmp)
  --keep             keep the raw-class job dir on exit instead of removing it (D50)
  --fake             OFFLINE demo: an echo CC stand-in (no ds-capture, no API spend)
  --append SYSTEM    extra --append-system-prompt text passed to claude
  -h | --help        this help
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("serpent-share", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "", "listen address (default 127.0.0.1:<free port>)")
	claudeBin := fs.String("claude", "", "claude binary (default $CLAUDE_BIN, then PATH)")
	captureBin := fs.String("capture-bin", "", "ds-capture binary (default $DS_CAPTURE_BIN, then PATH, then sibling)")
	port := fs.Int("port", 0, "ds-capture egress-gateway port (0 = auto; never :18080)")
	scratch := fs.String("scratch", "", "job dir for the gateway CA + cassette (default under ~/tmp)")
	keep := fs.Bool("keep", false, "keep the raw-class job dir on exit (D50)")
	fake := fs.Bool("fake", false, "OFFLINE demo: an echo CC stand-in (no ds-capture, no API spend)")
	appendSys := fs.String("append", "", "extra --append-system-prompt text passed to claude")
	fs.Usage = func() { fmt.Fprint(os.Stderr, rootUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *port == protectedMonitorPort {
		fmt.Fprintf(os.Stderr, "serpent-share: refusing :%d — the protected shared monitor; omit --port to auto-pick\n", protectedMonitorPort)
		return 2
	}

	listenAddr := *addr
	if listenAddr == "" {
		p, err := freePort()
		if err != nil {
			fmt.Fprintf(os.Stderr, "serpent-share: pick free port: %v\n", err)
			return 1
		}
		listenAddr = fmt.Sprintf("127.0.0.1:%d", p)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Stand up the CC process (real or fake) wired to a Bridge.
	cc, err := launchCC(ctx, ccOptions{
		fake:       *fake,
		claudeBin:  *claudeBin,
		captureBin: *captureBin,
		gwPort:     *port,
		scratch:    *scratch,
		keep:       *keep,
		appendSys:  *appendSys,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-share: %v\n", err)
		return 1
	}
	defer cc.cleanup()

	hub := newHub(cc.bridge)

	// Pump CC stdout → attach.Events → fan-out to every subscriber. When Pump
	// returns (CC EOF / exit), cancel the server so the process winds down.
	pumpCtx, pumpCancel := context.WithCancel(ctx)
	go func() {
		defer pumpCancel()
		_ = cc.bridge.Pump(pumpCtx, cc.stdout)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/ws", hub.handleWS)

	srv := &http.Server{Addr: listenAddr, Handler: mux}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-share: listen %s: %v\n", listenAddr, err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "serpent-share: shared Claude Code session up\n")
	fmt.Fprintf(os.Stderr, "  open in TWO browsers:  http://%s/\n", ln.Addr().String())
	if *fake {
		fmt.Fprintf(os.Stderr, "  (fake/echo CC — offline demo, no API spend)\n")
	}
	fmt.Fprintf(os.Stderr, "  D141: shared stdin; imperfect interleaving is ACCEPTED. Ctrl-C to stop.\n")

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case <-pumpCtx.Done():
		fmt.Fprintf(os.Stderr, "serpent-share: CC session ended — shutting down\n")
	case <-ctx.Done():
		fmt.Fprintf(os.Stderr, "serpent-share: signal — shutting down\n")
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "serpent-share: serve: %v\n", err)
		}
	}

	// Drain: close input, shut the HTTP server, let the process exit.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
	_ = cc.bridge.Close()
	pumpCancel()
	return 0
}

// --- the hub: N browser WS connections over one shared Bridge ----------------

// hub fans the Bridge out to every connected browser and fans every browser's
// keystrokes IN to the single shared CC stdin. It is the demo's shared-keyboard
// multiplexer: every connection is both a Subscriber (broadcast OUT) and a writer
// (DriveInput IN), with no seat arbitration — that is the D141 point.
type hub struct {
	bridge *hostbridge.Bridge
	nextID atomic.Int64
}

func newHub(b *hostbridge.Bridge) *hub { return &hub{bridge: b} }

// clientLabel maps a small connection id to a short author tag ([A], [B], …).
func clientLabel(id int64) string {
	// A..Z then A2.. — demo-grade, just needs to be visually distinct.
	letter := rune('A' + (id % 26))
	if id < 26 {
		return string(letter)
	}
	return fmt.Sprintf("%c%d", letter, id/26+1)
}

// handleWS upgrades an HTTP connection to a (minimal, RFC6455) WebSocket, then:
//   - registers a per-connection Subscriber that relays every projected
//     attach.Event to THIS browser (the fan-out leg), backfilling the session so
//     far from the Bridge resume ring so a late joiner sees prior output;
//   - reads inbound WS text frames (this browser's keystrokes/lines) and calls
//     bridge.DriveInput with the text tagged by the per-client label (the shared
//     fan-in leg). Every client writes to the SAME stdin under stdinMu.
func (h *hub) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrade(w, r)
	if err != nil {
		return // upgrade already wrote the failure
	}
	defer conn.Close()

	id := h.nextID.Add(1)
	label := clientLabel(id)

	// One write mutex per socket: the Subscriber goroutine and the inbound-read
	// loop both write control/text frames; serialize them.
	var wmu sync.Mutex
	writeJSON := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		wmu.Lock()
		defer wmu.Unlock()
		return conn.WriteText(b)
	}

	// Greet: tell the browser which author tag it is.
	_ = writeJSON(outMsg{Kind: "hello", Label: label})

	// Backfill the session so far from the Bridge's resume ring (ReplayFrom(0) =
	// "from the beginning of what is retained"), so a 2nd/late joiner sees prior
	// output before live events start streaming.
	if prior, rErr := h.bridge.ReplayFrom(0); rErr == nil {
		for _, ev := range prior {
			_ = writeJSON(eventMsg(ev))
		}
	}

	// Register the fan-out Subscriber. Its OnEvent relays each event to THIS
	// socket; a write error (browser gone) just drops — the read loop's exit
	// unsubscribes. Buffer through a channel so a slow socket never blocks the
	// shared pump (the Bridge fans out synchronously).
	evCh := make(chan attach.Event, 256)
	sub := &wsSubscriber{ch: evCh}
	unsub := h.bridge.Subscribe(sub)
	defer unsub()

	// Relay goroutine: drain the per-connection buffer to the socket.
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		for ev := range evCh {
			if err := writeJSON(eventMsg(ev)); err != nil {
				return
			}
		}
		// Stream closed: tell the browser.
		_ = writeJSON(outMsg{Kind: "closed"})
	}()

	// Inbound read loop: every text frame is this browser's input. Tag it with
	// the author label and DriveInput onto the SHARED stdin. Empty/whitespace
	// lines are dropped (EncodeInput rejects empty Text).
	for {
		data, err := conn.ReadText()
		if err != nil {
			break
		}
		var in inMsg
		if json.Unmarshal(data, &in) != nil {
			continue
		}
		text := in.Text
		if text == "" {
			continue
		}
		tagged := fmt.Sprintf("[%s] %s", label, text)
		if derr := h.bridge.DriveInput(hostbridge.DriveInput{Text: tagged}); derr != nil {
			_ = writeJSON(outMsg{Kind: "error", Text: derr.Error()})
			if errors.Is(derr, hostbridge.ErrInputClosed) {
				break
			}
		}
	}

	sub.close() // stop the relay goroutine
	<-relayDone
}

// wsSubscriber bridges a hostbridge.Subscriber to a per-connection buffered
// channel. OnEvent never blocks the shared pump: if the buffer is full (a slow
// browser), the event is DROPPED for this connection (the browser can resume from
// the ring on reconnect — demo-grade). OnClose closes the channel so the relay
// goroutine exits.
type wsSubscriber struct {
	ch     chan attach.Event
	once   sync.Once
	closed atomic.Bool
}

func (s *wsSubscriber) OnEvent(ev attach.Event) {
	if s.closed.Load() {
		return
	}
	select {
	case s.ch <- ev:
	default: // slow browser: drop (demo-grade); broadcast is best-effort here.
	}
}

func (s *wsSubscriber) OnClose(error) { s.close() }

func (s *wsSubscriber) close() {
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.ch)
	})
}

// --- wire messages (browser <-> server) --------------------------------------

// inMsg is a browser->server frame: a line/keystroke the user typed.
type inMsg struct {
	Text string `json:"text"`
}

// outMsg is a server->browser frame. Kind discriminates: "hello" (label
// assignment), "event" (a projected attach.Event, carried in Event), "closed"
// (the session stream ended), "error" (a drive error to surface).
type outMsg struct {
	Kind  string        `json:"kind"`
	Label string        `json:"label,omitempty"`
	Text  string        `json:"text,omitempty"`
	Event *attach.Event `json:"event,omitempty"`
}

func eventMsg(ev attach.Event) outMsg {
	e := ev
	return outMsg{Kind: "event", Event: &e}
}

// --- static UI ---------------------------------------------------------------

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "index missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// --- CC launch (real via ds-capture, or fake/echo) ---------------------------

type ccOptions struct {
	fake       bool
	claudeBin  string
	captureBin string
	gwPort     int
	scratch    string
	keep       bool
	appendSys  string
}

// ccProcess is a launched CC (real child or fake) wired to a Bridge.
type ccProcess struct {
	bridge  *hostbridge.Bridge
	stdout  io.Reader
	cleanup func()
}

// launchCC stands up the CC side: in --fake mode an in-process echo CC (no
// network, no API spend); otherwise the ds-capture gateway + a real local claude
// child driven via --print stream-json, egress routed through the gateway.
func launchCC(ctx context.Context, o ccOptions) (*ccProcess, error) {
	if o.fake {
		return launchFakeCC(), nil
	}

	captureBinPath, err := resolveCaptureBin(o.captureBin)
	if err != nil {
		return nil, err
	}
	claudePath, err := resolveClaudeBin(o.claudeBin)
	if err != nil {
		return nil, err
	}
	sess, gwCleanup, err := setupGateway(captureBinPath, o.gwPort, o.scratch, o.keep)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "serpent-share: egress gateway up on :%d (job dir: %s)\n", sess.port, sess.jobDir)

	// Launch the real local claude as a PLAIN child (no podman, no KVM) — the
	// ccCommand seam realized for a local process. --print stream-json is the
	// line/turn-granular drive the Bridge feeds: each DriveInput is one input
	// record; CC re-emits a system/init + result per input (DRIVE-FINDINGS), and
	// sustained multi-turn over one process is proven by the script.go scenario.
	ccArgs := []string{
		"--print",
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--verbose",
	}
	if o.appendSys != "" {
		ccArgs = append(ccArgs, "--append-system-prompt", o.appendSys)
	}
	cmd := exec.CommandContext(ctx, claudePath, ccArgs...)
	cmd.Env = append(os.Environ(), proxyEnv(sess.port, sess.caFile)...)
	cmd.Stderr = os.Stderr

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		gwCleanup()
		return nil, fmt.Errorf("claude stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		gwCleanup()
		return nil, fmt.Errorf("claude stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		gwCleanup()
		return nil, fmt.Errorf("start claude: %w", err)
	}
	fmt.Fprintf(os.Stderr, "serpent-share: launched %s (--print stream-json)\n", claudePath)

	b := hostbridge.NewBridge(stdinPipe, hostbridge.BridgeConfig{})

	cleanup := func() {
		_ = b.CloseInput() // closes stdinPipe → signals end-of-input to CC
		// Give CC a moment to flush its terminal result, then reap.
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		gwCleanup()
	}
	return &ccProcess{bridge: b, stdout: stdoutPipe, cleanup: cleanup}, nil
}

// --- resolution + gateway helpers (mirrors client/cmd/serpent) ---------------

type gatewaySession struct {
	jobDir, caFile, cassette string
	port                     int
	gw                       *gateway
}

func setupGateway(captureBin string, port int, scratch string, keep bool) (*gatewaySession, func(), error) {
	if port == 0 {
		p, err := freePort()
		if err != nil {
			return nil, nil, fmt.Errorf("pick free port: %w", err)
		}
		port = p
	}
	jobDir := scratch
	if jobDir == "" {
		d, err := os.MkdirTemp(scratchRoot(), "serpent-share-")
		if err != nil {
			return nil, nil, fmt.Errorf("job dir: %w", err)
		}
		jobDir = d
	} else if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("job dir: %w", err)
	}
	cassette := filepath.Join(jobDir, "gateway-cassette.json")
	caDir := filepath.Join(jobDir, "ca")
	caFile := filepath.Join(caDir, "ds-capture-ca.pem")
	gwLog := filepath.Join(jobDir, "gateway.log")

	gw, err := startGateway(captureBin, port, cassette, caDir, gwLog)
	if err != nil {
		if !keep {
			os.RemoveAll(jobDir)
		}
		return nil, nil, fmt.Errorf("%v (see %s)", err, gwLog)
	}
	if err := gw.waitReady(port, caFile, 15*time.Second); err != nil {
		gw.stop()
		if !keep {
			os.RemoveAll(jobDir)
		}
		return nil, nil, fmt.Errorf("%v (see %s)", err, gwLog)
	}
	sess := &gatewaySession{jobDir: jobDir, caFile: caFile, cassette: cassette, port: port, gw: gw}
	cleanup := func() {
		gw.stop()
		if !keep {
			os.RemoveAll(jobDir)
		}
	}
	return sess, cleanup, nil
}

func proxyEnv(port int, caFile string) []string {
	p := fmt.Sprintf("http://127.0.0.1:%d", port)
	return []string{
		"HTTPS_PROXY=" + p,
		"HTTP_PROXY=" + p,
		"NODE_USE_ENV_PROXY=1",
		"NODE_EXTRA_CA_CERTS=" + caFile,
	}
}

type gateway struct {
	cmd     *exec.Cmd
	done    chan error
	stopped chan struct{}
}

func startGateway(bin string, port int, cassette, caDir, logPath string) (*gateway, error) {
	lf, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("gateway log: %w", err)
	}
	cmd := exec.Command(bin, "record",
		"--port", fmt.Sprint(port), "--cassette", cassette, "--ca-dir", caDir)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return nil, fmt.Errorf("start ds-capture gateway: %w", err)
	}
	g := &gateway{cmd: cmd, done: make(chan error, 1), stopped: make(chan struct{})}
	go func() {
		g.done <- cmd.Wait()
		close(g.done)
		lf.Close()
	}()
	return g, nil
}

func (g *gateway) stop() {
	if g == nil || g.cmd == nil || g.cmd.Process == nil {
		return
	}
	select {
	case <-g.stopped:
		return
	default:
		close(g.stopped)
	}
	_ = g.cmd.Process.Signal(syscall.SIGINT)
	select {
	case <-g.done:
	case <-time.After(5 * time.Second):
		_ = g.cmd.Process.Kill()
		<-g.done
	}
}

func (g *gateway) waitReady(port int, caFile string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		select {
		case err := <-g.done:
			return fmt.Errorf("ds-capture gateway exited before it was ready (%v) — is :%d already in use?", err, port)
		default:
		}
		if _, statErr := os.Stat(caFile); statErr == nil {
			if c, dErr := net.DialTimeout("tcp", addr, 200*time.Millisecond); dErr == nil {
				_ = c.Close()
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ds-capture gateway did not come up on :%d within %s", port, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func resolveCaptureBin(explicit string) (string, error) {
	for _, c := range []string{explicit, os.Getenv("DS_CAPTURE_BIN")} {
		if c == "" {
			continue
		}
		if isExecutable(c) {
			return c, nil
		}
		return "", fmt.Errorf("ds-capture binary %q is not executable", c)
	}
	if p, err := exec.LookPath("ds-capture"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "ds-capture")
		if isExecutable(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("ds-capture not found — build it and put it on PATH:\n" +
		"    go build -o .bin/ds-capture ./client/cmd/ds-capture   (then PATH=.bin:$PATH, or pass --capture-bin)")
}

func resolveClaudeBin(explicit string) (string, error) {
	for _, c := range []string{explicit, os.Getenv("CLAUDE_BIN")} {
		if c == "" {
			continue
		}
		if isExecutable(c) {
			return c, nil
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("claude binary %q not found or not executable", c)
	}
	if p, err := exec.LookPath("claude"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("claude not found on PATH (pass --claude PATH or set CLAUDE_BIN)")
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func scratchRoot() string {
	if r := os.Getenv("DS_WT_ROOT"); r != "" {
		_ = os.MkdirAll(r, 0o755)
		return r
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		r := filepath.Join(home, "tmp")
		if os.MkdirAll(r, 0o755) == nil {
			return r
		}
	}
	return ""
}
