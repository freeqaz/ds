// SPDX-License-Identifier: Apache-2.0

package passthrough

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Tag is the single-sourced guardrail tag for this row (doc.go REGISTRATION).
const Tag = "pass-through-empty-by-default"

// ── The synthetic pass-through-config picture (doc 12 §5.3; D17/D74) ─────────

// Endpoint is one endpoint in the synthetic pass-through configuration.
type Endpoint struct {
	// Host labels the endpoint for messages (e.g. "pinned.example.com").
	Host string `json:"host"`
	// PassThrough is true iff this endpoint is on the cert-pinned pass-through
	// list (D17/D74): it gets an opaque tunnel with no inspection / swap /
	// scanning. The baseline pack (IsDefault) must carry NONE of these.
	PassThrough bool `json:"pass_through"`
	// TLSTerminated is true iff this endpoint's flow was TLS-terminated at the
	// per-session CA (D17) and ran through the inspected chain. Everything NOT on
	// the pass-through list must be terminated.
	TLSTerminated bool `json:"tls_terminated"`
	// SwapPerformed is true iff a credential swap was performed on this endpoint.
	// A pass-through-listed endpoint must have NO swap (the tunnel is opaque,
	// D17/D74); the swap belongs only on the terminated inspected path.
	SwapPerformed bool `json:"swap_performed"`
}

// Config is a synthetic fixture's full pass-through configuration picture.
type Config struct {
	// Name labels the fixture (filled from the filename when loaded via Load).
	Name string `json:"-"`
	// IsDefault is true iff this is the shipped baseline pack (D64). The
	// empty-by-default invariant binds ONLY the default config; an explicitly
	// configured, evidence-backed config (IsDefault=false) may carry entries.
	IsDefault bool `json:"is_default"`
	// Endpoints is the set of endpoints this configuration covers.
	Endpoints []Endpoint `json:"endpoints"`
}

// passThroughList returns the hosts on the pass-through list.
func (c Config) passThroughList() []string {
	var hosts []string
	for _, e := range c.Endpoints {
		if e.PassThrough {
			hosts = append(hosts, e.label())
		}
	}
	return hosts
}

// ── Violation taxonomy ──────────────────────────────────────────────────────

// ViolationClass names the failure modes this row enumerates.
type ViolationClass string

const (
	// ViolationNonemptyDefault — (a) the shipped baseline (is_default) carries a
	// non-empty pass-through list (forbidden by D74).
	ViolationNonemptyDefault ViolationClass = "default-pass-through-list-not-empty"
	// ViolationSwapOnPassThrough — (b) a swap was performed on a pass-through
	// endpoint (the tunnel must be opaque, D17/D74).
	ViolationSwapOnPassThrough ViolationClass = "credential-swap-on-pass-through-endpoint"
	// ViolationUnterminatedNonPassThrough — (c) a non-listed endpoint whose flow
	// was not TLS-terminated at the per-session CA (D17).
	ViolationUnterminatedNonPassThrough ViolationClass = "non-pass-through-endpoint-not-tls-terminated"
)

// Violation is a single failure: which rule, which subject, and a reason.
type Violation struct {
	Class   ViolationClass
	Subject string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Subject, v.Reason)
}

// ── The mechanical check ────────────────────────────────────────────────────

// Check diffs a synthetic pass-through configuration against the D17/D74
// invariant and returns every violation, in a stable order. An empty result
// means the configuration conforms.
//
// Verdict:
//
//   - IsDefault and the pass-through list is non-empty → NonemptyDefault (a).
//   - any pass-through endpoint with SwapPerformed → SwapOnPassThrough (b).
//   - any non-pass-through endpoint not TLSTerminated → UnterminatedNonPassThrough (c).
func Check(c Config) []Violation {
	var vs []Violation
	if c.IsDefault {
		if list := c.passThroughList(); len(list) > 0 {
			vs = append(vs, Violation{
				Class:   ViolationNonemptyDefault,
				Subject: c.label(),
				Reason: fmt.Sprintf("the shipped baseline pack (is_default=true) carries a non-empty "+
					"pass-through list %v; the D17 pass-through list ships EMPTY by default (D74) — an "+
					"entry must be added deliberately with attached reproduction evidence, never shipped "+
					"in the baseline (doc 12 §5.3)", list),
			})
		}
	}
	for _, e := range c.Endpoints {
		if e.PassThrough && e.SwapPerformed {
			vs = append(vs, Violation{
				Class:   ViolationSwapOnPassThrough,
				Subject: e.label(),
				Reason: fmt.Sprintf("endpoint %s is on the pass-through list yet a credential swap was "+
					"performed on it; a pass-through tunnel is OPAQUE — no inspection, no swap, no "+
					"scanning (D17/D74, doc 12 §5.3)", e.label()),
			})
		}
		if !e.PassThrough && !e.TLSTerminated {
			vs = append(vs, Violation{
				Class:   ViolationUnterminatedNonPassThrough,
				Subject: e.label(),
				Reason: fmt.Sprintf("endpoint %s is NOT on the pass-through list yet its flow was not "+
					"TLS-terminated at the per-session CA; everything not pass-through-listed must be "+
					"terminated (full-visibility egress by default, D17)", e.label()),
			})
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Subject < vs[j].Subject
	})
	return vs
}

// label names the endpoint for messages, with a fallback when blank.
func (e Endpoint) label() string {
	if e.Host != "" {
		return e.Host
	}
	return "(unnamed endpoint)"
}

// label names the config for messages, with a fallback when blank.
func (c Config) label() string {
	if c.Name != "" {
		return c.Name
	}
	return "(unnamed config)"
}

// ── Loading fixtures (cwd-independent) ──────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored).
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// validate rejects a config with no endpoints (a pass-through picture must cover
// at least one endpoint to anchor a verdict).
func (c Config) validate() error {
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("config %s declares no endpoints — a pass-through picture must cover at "+
			"least one endpoint", c.Name)
	}
	return nil
}

// Load reads a synthetic pass-through configuration from a JSON file and labels
// it with the file's base name for violation messages.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading pass-through config fixture %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parsing pass-through config fixture %s: %w", path, err)
	}
	c.Name = filepath.Base(path)
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
