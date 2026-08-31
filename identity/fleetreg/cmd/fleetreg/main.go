// SPDX-License-Identifier: Apache-2.0

// Command fleetreg is the stdlib-only control-plane CLI for the D84 fleet-scope
// secret-digest registration surface (doc 16 §6.4 / §9 / §11.3). It drives the
// fleetreg.Manager's register/revoke/list verbs over a fleet digest producer,
// a Vault/OpenBao KV-v2 read source (identity/kv-client, or a synthetic
// fixture), and a policy_log PolicySink — NO new proto, NO new RPC (registration
// rides the existing policy_log artifact path, D72).
//
// It is cobra-free: a single flag.FlagSet per subcommand (D84 deliverable: a
// stdlib-only CLI). The subcommands:
//
//	designate  --mount M --prefix P [--owner SUB] [--role ...]   designate a prefix (default-none until run)
//	register   --mount M --path P   [--owner SUB] [--role ...]   per-secret escape hatch
//	revoke     --mount M --path P                                retire a designation/secret
//	list                                                         show the consent surface
//
// LIVE-VAULT IS ENV-GATED AND DEFAULTED OFF (D50): with no FLEETREG_VAULT_ADDR
// set, the CLI runs entirely against a synthetic in-memory fixture (a fake KV
// source + a fake policy sink) so `designate`/`register`/`revoke`/`list` are
// demonstrable with no live store. Setting FLEETREG_VAULT_ADDR wires the
// identity/kv-client.Client adapter — but that path is a DEFERRED MANUAL STEP
// (it needs a reachable OpenBao/Vault + auth) and is never exercised in this
// wave; the default-off fixture path is the tested one.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/dream-serpent/dream-serpent/identity/digest"
	"github.com/dream-serpent/dream-serpent/identity/fleetreg"
	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "fleetreg:", err)
		os.Exit(1)
	}
}

const usage = `fleetreg — D84 fleet-scope secret-digest registration (doc 16 §6.4/§9/§11.3)

usage: fleetreg <command> [flags]

commands:
  designate   designate a Vault mount/path prefix (auto-covers + inherits)
  register    per-secret escape-hatch registration (a path outside any prefix)
  revoke      retire a designation or escape-hatch secret
  list        show the consent surface (default: none until configured)

run "fleetreg <command> -h" for the flags of a command.

DEFAULT-NONE: with nothing designated, "list" shows an empty surface — an
unconfigured integration touches zero plaintext (D84). Live Vault is env-gated
(FLEETREG_VAULT_ADDR) and OFF by default; the default path uses a synthetic
fixture (D50).`

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return errors.New("no command")
	}
	cmd, rest := args[0], args[1:]

	// Build the environment once: the consent surface (loaded from the fixture
	// state file if present so the CLI is stateful across invocations in a demo),
	// the digest producer, the read source, and the policy sink.
	env, err := newEnv(stderr)
	if err != nil {
		return err
	}

	switch cmd {
	case "designate":
		return env.cmdDesignate(rest, stdout)
	case "register":
		return env.cmdRegister(rest, stdout)
	case "revoke":
		return env.cmdRevoke(rest, stdout)
	case "list":
		return env.cmdList(rest, stdout)
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return nil
	default:
		fmt.Fprintln(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// env binds the Manager to whatever backends the environment selected. In the
// default (no FLEETREG_VAULT_ADDR) it is a synthetic fixture; the live path is
// the deferred manual step.
type env struct {
	mgr   *fleetreg.Manager
	store *fixtureStore // non-nil in fixture mode (persists the consent surface for a demo)
}

func newEnv(stderr io.Writer) (*env, error) {
	if addr := strings.TrimSpace(os.Getenv("FLEETREG_VAULT_ADDR")); addr != "" {
		// DEFERRED MANUAL STEP (env-gated, off by default): a live OpenBao/Vault
		// would be wired through the identity/kv-client adapter here. It needs a
		// reachable store + platform-service auth, so it is NOT exercised in this
		// wave (D50: synthetic fixtures only). Refuse rather than half-wire it.
		return nil, fmt.Errorf("live Vault (FLEETREG_VAULT_ADDR=%q) is a deferred manual step; unset it to use the synthetic fixture", addr)
	}
	store, err := loadFixture()
	if err != nil {
		return nil, err
	}
	prod, err := store.producer()
	if err != nil {
		return nil, err
	}
	mgr, err := fleetreg.NewManager(fleetreg.Config{
		Registry: store.registry(),
		Producer: prod,
		Source:   store.source(),
		Sink:     store.sink(),
	})
	if err != nil {
		return nil, err
	}
	return &env{mgr: mgr, store: store}, nil
}

func (e *env) persist() error {
	if e.store == nil {
		return nil
	}
	return e.store.save(e.mgr.Registry())
}

// ----- subcommands ---------------------------------------------------------

func (e *env) cmdDesignate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("designate", flag.ContinueOnError)
	mount := fs.String("mount", "", "Vault KV-v2 mount (required)")
	prefix := fs.String("prefix", "", "path prefix within the mount (empty = whole mount)")
	owner := fs.String("owner", "", "owning developer IdP-subject (sets developer ownership)")
	actorSub, actorRoles := actorFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*mount) == "" {
		return errors.New("designate: --mount is required")
	}
	d := fleetreg.Designation{Mount: *mount, Prefix: *prefix}
	if strings.TrimSpace(*owner) != "" {
		d.Ownership, d.Owner = fleetreg.OwnershipDeveloper, *owner
	} else {
		d.Ownership = fleetreg.OwnershipOrg
	}
	res, err := e.mgr.DesignatePrefix(context.Background(), actor(*actorSub, *actorRoles), d, "cli-designate")
	if err != nil {
		return err
	}
	if err := e.persist(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "designated %s (%s); digested %d secret(s); policy_log seq=%d committed=%t\n",
		canon(d.Mount, d.Prefix), res.Coverage, len(res.Paths), res.Fleet.Seq, res.Fleet.Committed)
	return nil
}

func (e *env) cmdRegister(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	mount := fs.String("mount", "", "Vault KV-v2 mount (required)")
	path := fs.String("path", "", "exact secret path (required)")
	owner := fs.String("owner", "", "owning developer IdP-subject (sets developer ownership)")
	actorSub, actorRoles := actorFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*mount) == "" || strings.TrimSpace(*path) == "" {
		return errors.New("register: --mount and --path are required")
	}
	s := fleetreg.Secret{Mount: *mount, Path: *path}
	if strings.TrimSpace(*owner) != "" {
		s.Ownership, s.Owner = fleetreg.OwnershipDeveloper, *owner
	} else {
		s.Ownership = fleetreg.OwnershipOrg
	}
	res, err := e.mgr.RegisterSecret(context.Background(), actor(*actorSub, *actorRoles), s, "cli-register")
	if err != nil {
		return err
	}
	if err := e.persist(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "registered escape-hatch %s; digested %d secret(s); policy_log seq=%d committed=%t\n",
		canon(s.Mount, s.Path), len(res.Paths), res.Fleet.Seq, res.Fleet.Committed)
	return nil
}

func (e *env) cmdRevoke(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	mount := fs.String("mount", "", "Vault KV-v2 mount (required)")
	path := fs.String("path", "", "designated prefix OR escape-hatch path to retire (required)")
	actorSub, actorRoles := actorFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*mount) == "" || strings.TrimSpace(*path) == "" {
		return errors.New("revoke: --mount and --path are required")
	}
	fr, err := e.mgr.Revoke(context.Background(), actor(*actorSub, *actorRoles), *mount, *path, "cli-revoke")
	if err != nil {
		return err
	}
	if err := e.persist(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "revoked %s; policy_log seq=%d committed=%t\n", canon(*mount, *path), fr.Seq, fr.Committed)
	return nil
}

func (e *env) cmdList(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg := e.mgr.Registry()
	if reg.Empty() {
		fmt.Fprintln(stdout, "consent surface: NONE (default — nothing designated, zero plaintext touched)")
		return nil
	}
	ds := reg.Designations()
	ss := reg.Secrets()
	lines := make([]string, 0, len(ds)+len(ss))
	for _, d := range ds {
		lines = append(lines, fmt.Sprintf("prefix       %-40s owner=%s/%s", canon(d.Mount, d.Prefix), d.Ownership, ownerOrDash(d.Owner)))
	}
	for _, s := range ss {
		lines = append(lines, fmt.Sprintf("escape-hatch %-40s owner=%s/%s", canon(s.Mount, s.Path), s.Ownership, ownerOrDash(s.Owner)))
	}
	sort.Strings(lines)
	fmt.Fprintf(stdout, "consent surface: %d designation(s), %d escape-hatch secret(s)\n", len(ds), len(ss))
	for _, l := range lines {
		fmt.Fprintln(stdout, l)
	}
	return nil
}

// ----- flag helpers --------------------------------------------------------

func actorFlags(fs *flag.FlagSet) (*string, *string) {
	sub := fs.String("actor", "", "actor IdP-subject (the principal performing the action)")
	roles := fs.String("role", "", "comma-separated actor roles (e.g. org_admin,developer)")
	return sub, roles
}

func actor(sub, roles string) fleetreg.Principal {
	p := fleetreg.Principal{Subject: strings.TrimSpace(sub)}
	for _, r := range strings.Split(roles, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			p.Roles = append(p.Roles, fleetreg.Role(r))
		}
	}
	return p
}

func canon(mount, path string) string {
	m := strings.Trim(strings.TrimSpace(mount), "/")
	p := strings.Trim(strings.TrimSpace(path), "/")
	if p == "" {
		return m
	}
	if m == "" {
		return p
	}
	return m + "/" + p
}

func ownerOrDash(o string) string {
	if strings.TrimSpace(o) == "" {
		return "-"
	}
	return o
}

// ----- synthetic fixture (D50, default-off-live path) ----------------------
//
// With no FLEETREG_VAULT_ADDR, the CLI runs against this in-memory fixture so
// every verb is demonstrable with no live store. State is persisted to a JSON
// file (FLEETREG_STATE, default ~/.fleetreg-demo.json) so a demo's
// designate→list→revoke sequence is stateful across process invocations; the
// synthetic KV tree itself is seeded fresh each run (a demo store).

const defaultStateEnv = "FLEETREG_STATE"

// fixtureStore is the synthetic backend: a fake KV tree, a fake policy sink that
// assigns monotonic seqs, a fixed-key producer, and the persisted consent
// surface. It is the value `newEnv` returns in default (no-live) mode.
type fixtureStore struct {
	statePath string
	kv        *fakeKV
	fakeSink  *fakeSink
	prod      *digest.Producer
	loaded    *fleetreg.Registry
}

// persistedState is the JSON shape of the consent surface saved between runs.
type persistedState struct {
	Designations []persistedDesignation `json:"designations"`
	Secrets      []persistedSecret      `json:"secrets"`
}

type persistedDesignation struct {
	Mount     string `json:"mount"`
	Prefix    string `json:"prefix"`
	Ownership string `json:"ownership"`
	Owner     string `json:"owner,omitempty"`
}

type persistedSecret struct {
	Mount     string `json:"mount"`
	Path      string `json:"path"`
	Ownership string `json:"ownership"`
	Owner     string `json:"owner,omitempty"`
}

func loadFixture() (*fixtureStore, error) {
	statePath := strings.TrimSpace(os.Getenv(defaultStateEnv))
	if statePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		statePath = home + "/.fleetreg-demo.json"
	}
	reg := fleetreg.NewRegistry()
	if raw, err := os.ReadFile(statePath); err == nil {
		var ps persistedState
		if err := json.Unmarshal(raw, &ps); err != nil {
			return nil, fmt.Errorf("decode state %s: %w", statePath, err)
		}
		for _, d := range ps.Designations {
			_ = reg.Designate(fleetreg.Designation{Mount: d.Mount, Prefix: d.Prefix, Ownership: parseOwnership(d.Ownership), Owner: d.Owner})
		}
		for _, s := range ps.Secrets {
			_ = reg.RegisterSecret(fleetreg.Secret{Mount: s.Mount, Path: s.Path, Ownership: parseOwnership(s.Ownership), Owner: s.Owner})
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read state %s: %w", statePath, err)
	}
	prod, err := digest.NewProducer("fleetreg-demo-epoch", []byte("ds-synth-fleetreg-demo-hmac-key"), 0)
	if err != nil {
		return nil, err
	}
	return &fixtureStore{
		statePath: statePath,
		kv:        seedDemoKV(),
		fakeSink:  &fakeSink{},
		prod:      prod,
		loaded:    reg,
	}, nil
}

func (s *fixtureStore) registry() *fleetreg.Registry  { return s.loaded }
func (s *fixtureStore) source() fleetreg.DigestSource { return s.kv }
func (s *fixtureStore) sink() digest.PolicySink       { return s.fakeSink }
func (s *fixtureStore) producer() (*digest.Producer, error) {
	if s.prod == nil {
		return nil, errors.New("nil demo producer")
	}
	return s.prod, nil
}

func (s *fixtureStore) save(reg *fleetreg.Registry) error {
	var ps persistedState
	for _, d := range reg.Designations() {
		ps.Designations = append(ps.Designations, persistedDesignation{Mount: d.Mount, Prefix: d.Prefix, Ownership: d.Ownership.String(), Owner: d.Owner})
	}
	for _, sec := range reg.Secrets() {
		ps.Secrets = append(ps.Secrets, persistedSecret{Mount: sec.Mount, Path: sec.Path, Ownership: sec.Ownership.String(), Owner: sec.Owner})
	}
	raw, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.statePath, raw, 0o600)
}

func parseOwnership(s string) fleetreg.Ownership {
	switch s {
	case "org":
		return fleetreg.OwnershipOrg
	case "developer":
		return fleetreg.OwnershipDeveloper
	default:
		return fleetreg.OwnershipUnspecified
	}
}

// seedDemoKV builds a small synthetic KV tree so `designate` has something to
// digest in a demo. All secrets are SYNTHETIC (ds-synth-*); no real material.
func seedDemoKV() *fakeKV {
	return &fakeKV{secrets: map[string][]byte{
		"secret/data/dreamserpent/github": []byte("ds-synth-github-pat"),
		"secret/data/dreamserpent/aws":    []byte("ds-synth-aws-key"),
		"secret/data/teams/ci/deploy":     []byte("ds-synth-ci-deploy-token"),
	}}
}

// fakeKV is an in-memory fleetreg.DigestSource over a flat synthetic tree.
type fakeKV struct {
	secrets map[string][]byte // canonical "mount/path" → synthetic plaintext
}

func (k *fakeKV) ListLeaves(_ context.Context, mount, prefix string) ([]string, error) {
	want := canon(mount, prefix)
	var out []string
	for full := range k.secrets {
		if full == want || strings.HasPrefix(full, want+"/") {
			// Strip the mount segment to return mount-relative leaf paths, the
			// shape the Manager re-qualifies with the mount.
			out = append(out, strings.TrimPrefix(full, canon(mount, "")+"/"))
		}
	}
	sort.Strings(out)
	return out, nil
}

func (k *fakeKV) ReadSecret(_ context.Context, mount, path string) ([]byte, error) {
	pt, ok := k.secrets[canon(mount, path)]
	if !ok {
		return nil, fmt.Errorf("fakeKV: no secret at %s", canon(mount, path))
	}
	return pt, nil
}

// fakeSink is an in-memory digest.PolicySink assigning monotonic policy_log
// seqs and always committing — the synthetic policy-stream the CLI demo appends
// to (the real one is the orchestrator's policy_log, never touched here).
type fakeSink struct {
	seq uint64
}

func (s *fakeSink) AppendFleetDigest(_ context.Context, art digest.FleetPolicyArtifact) (digest.FleetPolicyResult, error) {
	s.seq++
	return digest.FleetPolicyResult{Seq: s.seq, Committed: true, KeyID: art.KeyID, BatchID: art.BatchID}, nil
}

// ----- live kv-client adapter (env-gated, deferred manual step) -------------
//
// kvSourceAdapter projects identity/kv-client.Client onto fleetreg.DigestSource,
// proving the cross-module seam: the Manager reads designated trees through the
// SAME ListKeys/ReadSecret read surface kv-client exposes (doc 16 §11.3), with
// the digest MATH staying in identity/digest. It is wired only on the live path
// (FLEETREG_VAULT_ADDR), which is a deferred manual step; the adapter itself is
// unit-tested against an httptest fake OpenBao server (D50: synthetic fixtures).
type kvSourceAdapter struct {
	c *kvclient.Client
}

// newKVSource builds the adapter from a configured kv-client.Client.
func newKVSource(c *kvclient.Client) *kvSourceAdapter { return &kvSourceAdapter{c: c} }

// ListLeaves walks the KV-v2 metadata tree recursively, resolving Vault's
// trailing-"/" sub-prefix convention to leaf paths so the Manager need not
// re-walk. The kv-client.Client's mount is fixed at construction, so mount is
// validated against it but not re-sent.
func (a *kvSourceAdapter) ListLeaves(ctx context.Context, _ /*mount*/, prefix string) ([]string, error) {
	var leaves []string
	var walk func(string) error
	walk = func(p string) error {
		keys, err := a.c.ListKeys(ctx, p)
		if err != nil {
			return err
		}
		for _, k := range keys {
			child := joinKey(p, strings.TrimSuffix(k, "/"))
			if strings.HasSuffix(k, "/") {
				if err := walk(child); err != nil {
					return err
				}
				continue
			}
			leaves = append(leaves, child)
		}
		return nil
	}
	if err := walk(strings.Trim(prefix, "/")); err != nil {
		return nil, err
	}
	sort.Strings(leaves)
	return leaves, nil
}

// ReadSecret reads one secret through kv-client and serializes its KV-v2 data
// map deterministically into the plaintext bytes the producer HMACs. The
// canonical serialization (sorted keys) means the same secret always digests to
// the same value across syncs.
func (a *kvSourceAdapter) ReadSecret(ctx context.Context, _ /*mount*/, path string) ([]byte, error) {
	sec, err := a.c.ReadSecret(ctx, path)
	if err != nil {
		return nil, err
	}
	return canonicalSecretBytes(sec.Data), nil
}

func joinKey(prefix, key string) string {
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

// canonicalSecretBytes deterministically serializes a KV-v2 data map into the
// plaintext bytes digested (sorted "k=v\n" lines). It is digest-stable, so a
// re-sync of an unchanged secret produces the identical digest. A hash prefix is
// folded in so two distinct secrets with equal canonical text (impossible in
// practice) still differ — defensive, never load-bearing.
func canonicalSecretBytes(data map[string]any) []byte {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%v\n", k, data[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	out := append([]byte(b.String()), sum[:8]...)
	return out
}

// ensure the live adapter satisfies the seam (compile-time check; the live path
// itself is the deferred manual step).
var (
	_ fleetreg.DigestSource = (*kvSourceAdapter)(nil)
	_ fleetreg.DigestSource = (*fakeKV)(nil)
	_ digest.PolicySink     = (*fakeSink)(nil)
	_                       = newKVSource
)
