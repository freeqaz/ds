package e2e

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// boundedPipe is an in-memory pipe with a FIXED-CAPACITY buffer — the faithful
// model of an OS pipe between two processes. A Write blocks when the buffer is
// full until a Read drains it; a Read blocks when empty until a Write or Close.
// This is what makes the backpressure deadlock reproducible in memory: io.Pipe
// is fully synchronous (no buffer), so it cannot model the kernel pipe's bounded
// buffer where a writer races ahead and then stalls. A small capacity here
// stands in for the ~64KiB kernel pipe buffer at a fraction of the bytes.
type boundedPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	cap    int
	closed bool
}

func newBoundedPipe(capacity int) *boundedPipe {
	p := &boundedPipe{cap: capacity}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *boundedPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	written := 0
	for written < len(b) {
		for len(p.buf) >= p.cap && !p.closed {
			p.cond.Wait() // buffer full: block until a reader drains it.
		}
		if p.closed {
			return written, io.ErrClosedPipe
		}
		room := p.cap - len(p.buf)
		n := len(b) - written
		if n > room {
			n = room
		}
		p.buf = append(p.buf, b[written:written+n]...)
		written += n
		p.cond.Broadcast()
	}
	return written, nil
}

func (p *boundedPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 {
		if p.closed {
			return 0, io.EOF
		}
		p.cond.Wait() // empty: block until a writer fills it or closes.
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	p.cond.Broadcast()
	return n, nil
}

// Close marks the pipe done; pending reads return EOF, pending writes ErrClosedPipe.
func (p *boundedPipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cond.Broadcast()
	return nil
}

// fakeCC is an in-memory stand-in for a real CC process: a bounded stdin pipe it
// reads and a bounded stdout pipe it writes, wired so a test controls exactly
// when output appears relative to input consumption. It is NOT a CC adapter (no
// runtime vocabulary) — it is a byte-level pipe peer that lets the pump be
// tested without spawning anything. The bounded buffers reproduce the OS-pipe
// backpressure deadlock that defeats a sequential write-all-then-read driver.
type fakeCC struct {
	in  *boundedPipe // the pump writes here (process stdin); fakeCC reads it.
	out *boundedPipe // fakeCC writes here (process stdout); the pump reads it.
}

// newFakeCC builds a fakeCC with bounded buffers. capacity models the kernel
// pipe buffer (small, so the test drives little data yet still deadlocks a
// sequential driver).
func newFakeCC(capacity int) *fakeCC {
	return &fakeCC{in: newBoundedPipe(capacity), out: newBoundedPipe(capacity)}
}

// stdin returns the WriteCloser the pump drives (closing it ends the input).
func (f *fakeCC) stdin() io.WriteCloser { return f.in }

// stdout returns the Reader the pump projects.
func (f *fakeCC) stdout() io.Reader { return f.out }

// collector is a Projector that records every projected line, guarded for the
// concurrent pump.
type collector struct {
	mu    sync.Mutex
	lines [][]byte
	err   error // if set, Project returns it (fault injection).
}

func (c *collector) Project(line []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.lines = append(c.lines, append([]byte(nil), line...))
	return nil
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.lines)
}

// echoFakeCC runs a fakeCC that reads stdin line by line and ECHOES each line to
// stdout as it reads it — the natural CC behaviour (output interleaves with
// input consumption). Both ends are bounded pipes, so when the driver does NOT
// drain stdout, fakeCC's stdout write blocks once the stdout buffer fills, which
// stops it reading stdin, which blocks the driver's stdin write: the classic
// pipe deadlock. It returns the number of lines echoed and any error, and closes
// stdout at EOF so the pump's scanner terminates.
func echoFakeCC(f *fakeCC, payload []byte) (echoed *int, errp *error, wait func()) {
	n := 0
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer f.out.Close()
		sc := bufio.NewScanner(f.in)
		sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
		for sc.Scan() {
			if _, werr := f.out.Write(payload); werr != nil {
				err = werr
				return
			}
			if _, werr := f.out.Write([]byte("\n")); werr != nil {
				err = werr
				return
			}
			n++
		}
		err = sc.Err()
	}()
	return &n, &err, func() { <-done }
}

// TestDriveStreamsBackpressure is THE regression test. It models a CC that echoes
// each input to stdout as it consumes it, through BOUNDED pipes (the OS-pipe
// model). The total data driven (nInputs * inputSize) and the echoed output both
// far exceed the pipe capacity, so a sequential "write ALL inputs, THEN read
// stdout" driver deadlocks: it stalls filling stdin while fakeCC stalls filling
// the unread stdout buffer — neither side progresses. The concurrent pump must
// complete because it drains stdout while still feeding stdin.
//
// Bounded by an explicit wall-clock deadline so a regression is a test failure,
// not a hung suite.
func TestDriveStreamsBackpressure(t *testing.T) {
	const nInputs = 256
	const inputSize = 4 * 1024 // 1MiB driven, vs a 16KiB pipe — must backpressure.
	const pipeCap = 16 * 1024  // models the bounded kernel pipe buffer.

	inputs := make([][]byte, nInputs)
	for i := range inputs {
		inputs[i] = bytes.Repeat([]byte{'a' + byte(i%26)}, inputSize)
	}

	fcc := newFakeCC(pipeCap)
	echoed, fakeErrp, fakeWait := echoFakeCC(fcc, bytes.Repeat([]byte("z"), 2*1024))

	coll := &collector{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run the pump under a hard wall-clock bound: a deadlock regression blocks
	// here forever, so we assert it returns in time.
	done := make(chan error, 1)
	go func() { done <- driveStreams(ctx, fcc.stdin(), fcc.stdout(), inputs, coll) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("driveStreams returned error: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("driveStreams DEADLOCKED on backpressure: did not finish within 8s " +
			"(the sequential write-all-then-project shape deadlocks here; the concurrent pump must not)")
	}

	fakeWait()
	if *fakeErrp != nil {
		t.Fatalf("fakeCC error: %v", *fakeErrp)
	}
	if *echoed != nInputs {
		t.Fatalf("fakeCC echoed %d lines, want %d (one per driven input)", *echoed, nInputs)
	}
	// Every echoed line was projected back: the loop closed end-to-end.
	if got := coll.count(); got != nInputs {
		t.Fatalf("projected %d lines, want %d (one per driven input)", got, nInputs)
	}
}

// TestDriveStreamsClosesStdin asserts the writer closes stdin after the final
// input — the end-of-conversation signal CC needs. echoFakeCC's scanner returns
// EOF (ending the loop) only when stdin is closed; if it returns, close happened.
func TestDriveStreamsClosesStdin(t *testing.T) {
	fcc := newFakeCC(64 * 1024)
	inputs := [][]byte{[]byte(`{"type":"user"}`), []byte(`{"type":"user"}`)}
	echoed, fakeErrp, fakeWait := echoFakeCC(fcc, []byte("ok"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := driveStreams(ctx, fcc.stdin(), fcc.stdout(), inputs, &collector{}); err != nil {
		t.Fatalf("driveStreams: %v", err)
	}

	fakeWait()
	if *fakeErrp != nil {
		t.Fatalf("fakeCC error: %v", *fakeErrp)
	}
	if *echoed != len(inputs) {
		t.Fatalf("fakeCC read %d input lines, want %d (stdin not closed after the final input?)", *echoed, len(inputs))
	}
}

// TestDriveStreamsProjectorFault asserts a projector error aborts the drive and
// is the returned (firstErr) error.
func TestDriveStreamsProjectorFault(t *testing.T) {
	fcc := newFakeCC(64 * 1024)
	_, _, fakeWait := echoFakeCC(fcc, []byte("trigger"))

	wantErr := errors.New("boom")
	coll := &collector{err: wantErr}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := driveStreams(ctx, fcc.stdin(), fcc.stdout(), [][]byte{[]byte("x")}, coll)
	if !errors.Is(err, wantErr) {
		t.Fatalf("driveStreams error = %v, want %v", err, wantErr)
	}
	// Closing stdout (via ctx-independent fault path) lets fakeCC's scanner end.
	_ = fcc.in.Close()
	fakeWait()
}

// TestDriveStreamsContextCancel asserts ctx cancellation aborts the pump promptly
// and is the returned error (it dominates firstErr). fakeCC reads stdin but never
// writes stdout and never closes it, so the pump blocks on the reader until ctx
// fires and driveStreams closes the streams to unblock it.
func TestDriveStreamsContextCancel(t *testing.T) {
	fcc := newFakeCC(64 * 1024)
	// Drain stdin forever; never produce stdout, never close it.
	go func() { _, _ = io.Copy(io.Discard, fcc.in) }()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() { done <- driveStreams(ctx, fcc.stdin(), fcc.stdout(), [][]byte{[]byte("x")}, &collector{}) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("driveStreams error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("driveStreams did not abort on ctx cancellation")
	}
}

// --- DriveLive gate test ---------------------------------------------------

// TestDriveLiveGated asserts DriveLive never launches with DS_E2E_LIVE unset:
// it returns ErrLiveGateUnset without spawning anything. This is the single-gate
// story enforced in Go. The test explicitly unsets the gate so it is hermetic.
func TestDriveLiveGated(t *testing.T) {
	t.Setenv(LiveGateEnv, "") // ensure unset/non-"1".
	err := DriveLive(context.Background(), ".", SandboxArgv{
		CIABin: "/bin/true", Mode: ModeReplay, Cassette: "/work/cas.jsonl", NoEgress: true,
	}, [][]byte{[]byte("x")}, &collector{})
	if !errors.Is(err, ErrLiveGateUnset) {
		t.Fatalf("DriveLive with gate unset = %v, want ErrLiveGateUnset", err)
	}
}

// --- SandboxArgv <-> script argv-contract structural test ------------------

// TestSandboxArgvMatchesScriptUsage is the structural argv-contract test: it
// ties SandboxArgv's rendered flags to the flag set scripts/cc_sandbox.sh
// documents in its usage string, so the Go contract and the shell contract
// cannot drift apart silently. It reads the script source (it does NOT execute
// it) and asserts every flag SandboxArgv emits is a flag the script's usage
// names, and that the script's documented drive flags are all representable in
// SandboxArgv.
func TestSandboxArgvMatchesScriptUsage(t *testing.T) {
	scriptPath := locateScript(t)
	src, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	script := string(src)

	// 1. Every flag SandboxArgv.Args() can emit must appear in the script.
	full := SandboxArgv{CIABin: "/bin/true", Mode: ModeRecord, Cassette: "/work/cas.jsonl", BudgetUSD: "0.30"}
	for _, f := range flagsOf(full.Args()) {
		if !strings.Contains(script, f) {
			t.Errorf("SandboxArgv emits flag %q but scripts/cc_sandbox.sh never mentions it (contract drift)", f)
		}
	}
	// And the --no-egress variant's flag.
	if !strings.Contains(script, FlagNoEgress) {
		t.Errorf("SandboxArgv emits %q but the script never mentions it", FlagNoEgress)
	}

	// 2. Conversely, the canonical drive flags the script documents must each be
	// represented by a SandboxArgv field (no script flag is unreachable from Go).
	for _, f := range []string{FlagCIA, FlagMode, FlagCassette, FlagBudgetUSD, FlagNoEgress} {
		if !strings.Contains(script, f) {
			t.Errorf("expected drive flag %q is missing from the script — the harness assumes it exists", f)
		}
	}

	// 3. The single live gate and the retired gate: the script must name
	// DS_E2E_LIVE and must NOT arm on CC_SANDBOX_LIVE alone (it documents the
	// retirement). Assert both the presence of the new gate and the explicit
	// "retired" wording for the old one.
	if !strings.Contains(script, LiveGateEnv) {
		t.Errorf("script does not mention the single live gate %q", LiveGateEnv)
	}
	if strings.Contains(script, "CC_SANDBOX_LIVE") && !strings.Contains(script, "retired") {
		t.Errorf("script mentions CC_SANDBOX_LIVE but never marks it retired — the gate-vocabulary unification is unproven")
	}

	// 4. The record-mode network contract: the script must wire the :18080 proxy
	// env (HTTPS_PROXY/HTTP_PROXY + NODE_USE_ENV_PROXY=1) the harness's record
	// mode depends on, and must offer --network=none for the zero-egress path.
	for _, needle := range []string{"18080", "HTTPS_PROXY", "HTTP_PROXY", "NODE_USE_ENV_PROXY=1", "--network=none"} {
		if !strings.Contains(script, needle) {
			t.Errorf("script is missing the network contract token %q the harness relies on", needle)
		}
	}

	// 5. The actions the harness names must exist in the script.
	for _, action := range []string{ActionGate, ActionPlan, ActionGateThenPlan, ActionSelfCheck} {
		if !strings.Contains(script, action) {
			t.Errorf("script is missing the action %q the harness documents", action)
		}
	}
}

// TestSandboxArgvArgsShape asserts the rendered argv shape: the three required
// flags in order, then exactly one of the budget/no-egress pair.
func TestSandboxArgvArgsShape(t *testing.T) {
	cases := []struct {
		name string
		argv SandboxArgv
		want []string
	}{
		{
			name: "record with budget",
			argv: SandboxArgv{CIABin: "cia", Mode: ModeRecord, Cassette: "c.jsonl", BudgetUSD: "0.50"},
			want: []string{"--cia", "cia", "--mode", "record", "--cassette", "c.jsonl", "--budget-usd", "0.50"},
		},
		{
			name: "replay no-egress",
			argv: SandboxArgv{CIABin: "cia", Mode: ModeReplay, Cassette: "c.jsonl", NoEgress: true},
			want: []string{"--cia", "cia", "--mode", "replay", "--cassette", "c.jsonl", "--no-egress"},
		},
		{
			name: "no-egress wins over budget",
			argv: SandboxArgv{CIABin: "cia", Mode: ModeRecord, Cassette: "c.jsonl", BudgetUSD: "0.50", NoEgress: true},
			want: []string{"--cia", "cia", "--mode", "record", "--cassette", "c.jsonl", "--no-egress"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.argv.Args()
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("Args() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSandboxArgvValidate asserts Validate mirrors the script's G0 checks.
func TestSandboxArgvValidate(t *testing.T) {
	good := SandboxArgv{CIABin: "cia", Mode: ModeReplay, Cassette: "c.jsonl", NoEgress: true}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate(good) = %v, want nil", err)
	}
	bad := []SandboxArgv{
		{Mode: ModeReplay, Cassette: "c"},                                                // no cia
		{CIABin: "cia", Cassette: "c"},                                                   // no mode
		{CIABin: "cia", Mode: "bogus", Cassette: "c"},                                    // bad mode
		{CIABin: "cia", Mode: ModeRecord},                                                // no cassette
		{CIABin: "cia", Mode: ModeRecord, Cassette: "c", BudgetUSD: "1", NoEgress: true}, // budget meaningless
	}
	for i, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("Validate(bad[%d]=%+v) = nil, want error", i, b)
		}
	}
}

// --- helpers ---------------------------------------------------------------

// flagsOf returns the flag tokens (those starting with "--") from an argv slice.
func flagsOf(argv []string) []string {
	var out []string
	for _, a := range argv {
		if strings.HasPrefix(a, "--") {
			out = append(out, a)
		}
	}
	return out
}

// locateScript finds scripts/cc_sandbox.sh by walking up from the test's working
// directory (client/goldentrace/e2e) to the repo root. It skips the structural
// test if the script is absent — a sibling unit may not have landed it in this
// worktree — recording WHY, so the contract test never fails for a reason
// outside this unit's ownership.
func locateScript(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "scripts", "cc_sandbox.sh")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("scripts/cc_sandbox.sh not found walking up from cwd; the argv-contract test needs it co-located (it is owned by this unit)")
	return "" // unreachable
}
