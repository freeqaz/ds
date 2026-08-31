// SPDX-License-Identifier: Apache-2.0

// The generic OpenBao-compatible KV-v2 READ-ONLY client (doc 16 §11.3; D85 OSS).
//
// Surface, and ONLY this surface (§11.3 "KV v2 read-only in v0"):
//   - ReadSecret  — KV v2 read of a designated path, returning the swap-class
//     credential the registry binds (the §5.1/§5.2 swap fetch).
//   - ListKeys    — KV v2 list of a designated prefix, so the §6.4 digest hook
//     can WALK a designated tree. This client only EXPOSES the reads; the digest
//     math (keyed HMAC variants) lives in ../digest/ and never here (§6.4, the
//     "no digest computation" charter line).
//
// READ-ONLY IS STRUCTURAL, not a runtime flag. There is NO Write, NO Put, NO
// Delete, NO lease-create, NO dynamic-engine method ANYWHERE on this type — the
// posture is enforced BY CONSTRUCTION, so a caller cannot mutate the store even
// by mistake (§11.3; the D80 service-boundary discipline, never a flag inside a
// binary). Dynamic-secrets engines (database/AWS/PKI engines that mint on read)
// are the tracked OQ3 follow-on, left open — nothing here precludes it, but v0
// ships none of it.
//
// The client never holds a long-lived credential: it authenticates the PLATFORM
// SERVICE (auth.go), caches the short-lived Vault token, and re-logs in on a
// 403. No real key material anywhere — tested only against an httptest fake
// (D50; client_test.go).
package kvclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// maxResponseBytes caps every response body read. The Vault KV-v2 read/list and
// login replies are small JSON documents; the cap is a defensive bound against a
// hostile or runaway store, applied uniformly via io.LimitReader.
const maxResponseBytes = 4 << 20 // 4 MiB

// ErrSecretNotFound is returned when a KV-v2 read/list targets a path with no
// data (Vault 404). It is a definitive miss — distinct from ErrPermission (a
// scoping/auth problem) and from a transport error (availability).
var ErrSecretNotFound = errors.New("kvclient: no secret at path")

// ErrPermission is returned when the store denies the read (Vault 403): the
// platform service's Vault role is not scoped to the path. Under D84 this is the
// EXPECTED outcome for a path outside the designated mounts — designation and
// auth-scope are the same boundary (§11.3), so reading outside the designation
// fails closed here.
var ErrPermission = errors.New("kvclient: store denied read (path outside designated scope)")

// ErrUnexpectedStatus wraps any other non-200 store response.
var ErrUnexpectedStatus = errors.New("kvclient: unexpected store status")

// Client is the OpenBao-compatible KV-v2 READ-ONLY client. Construct it with
// New; it authenticates the platform service lazily on first read and caches the
// resulting short-lived Vault token, re-authenticating on a 403.
//
// The type exposes ONLY read methods (ReadSecret, ListKeys). The absence of any
// write/lease/dynamic method is the read-only posture (§11.3) — enforced by the
// type's surface, not by a guard a caller could bypass.
type Client struct {
	// addr is the store base address, e.g. "https://vault.example.com:8200".
	addr string
	// mount is the KV-v2 secrets-engine mount, e.g. "secret". KV v2 splits the
	// API path into <mount>/data/<path> for reads and <mount>/metadata/<path>
	// for lists; the client inserts data/ and metadata/ so callers pass the
	// logical path (§12: path conventions free, bounded by OpenBao compat).
	mount string
	// auth logs the platform service in (JWT/OIDC default, AppRole fallback).
	auth Authenticator
	// doer is the HTTP transport — a real *http.Client in production, an
	// httptest-backed client in tests (D50).
	doer httpDoer

	mu    sync.Mutex
	token string // cached short-lived Vault token; "" until first login
}

// Option configures a Client at construction.
type Option func(*Client)

// WithHTTPClient injects the HTTP transport. Tests pass an httptest server's
// client (D50); production passes a real *http.Client over HTTPS. When unset the
// client uses http.DefaultClient.
func WithHTTPClient(doer httpDoer) Option {
	return func(c *Client) { c.doer = doer }
}

// New builds a read-only KV-v2 client for the store at addr, reading from the
// KV-v2 engine mounted at mount, authenticating the platform service via auth.
// It validates its arguments but performs NO network I/O — login is lazy, on the
// first read, so construction never blocks on store availability (the D39
// availability dependency stalls reads, never construction).
func New(addr, mount string, auth Authenticator, opts ...Option) (*Client, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("kvclient: store address is empty")
	}
	if strings.TrimSpace(mount) == "" {
		return nil, errors.New("kvclient: kv mount is empty")
	}
	if auth == nil {
		return nil, errors.New("kvclient: authenticator is nil")
	}
	c := &Client{
		addr:  strings.TrimRight(addr, "/"),
		mount: strings.Trim(mount, "/"),
		auth:  auth,
		doer:  http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Secret is the result of a KV-v2 read: the credential material plus its KV-v2
// version. Data is the secret's key/value pairs (e.g. {"token": "ghp_..."}) —
// opaque to this client, which decides nothing about it (the charter "reads
// stored material, it decides nothing" line). The swap executor / grant service
// interprets it.
type Secret struct {
	// Data is the KV-v2 secret payload (data.data in the Vault response).
	Data map[string]any
	// Version is the KV-v2 version that was read (data.metadata.version).
	Version int
}

// ReadSecret reads the KV-v2 secret at the logical path under the configured
// mount — the §5.1/§5.2 swap-class fetch. It authenticates the platform service
// on first use and on a 403, then GETs <mount>/data/<path>.
//
// This is a READ. There is no companion write: the read-only posture (§11.3) is
// the absence of a write method, not a parameter on this one.
func (c *Client) ReadSecret(ctx context.Context, path string) (Secret, error) {
	logical := strings.Trim(path, "/")
	if logical == "" {
		return Secret{}, errors.New("kvclient: read path is empty")
	}
	apiPath := c.mount + "/data/" + logical

	payload, err := c.authedGet(ctx, apiPath, nil)
	if err != nil {
		return Secret{}, err
	}

	var kr struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &kr); err != nil {
		return Secret{}, fmt.Errorf("kvclient: decode kv-v2 read: %w", err)
	}
	return Secret{Data: kr.Data.Data, Version: kr.Data.Metadata.Version}, nil
}

// ListKeys lists the immediate child keys under the logical prefix via the KV-v2
// metadata endpoint — the §6.4 digest-tree WALK. The digest producer uses this
// to enumerate a D84-designated tree; this client returns key names ONLY (no
// plaintext) so the producer can then ReadSecret each leaf. A trailing "/" in a
// returned key denotes a sub-prefix, the Vault list convention.
//
// This is the read side of §6.4. It computes no digest (that is ../digest/'s) —
// it only exposes the enumeration the producer needs.
func (c *Client) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	logical := strings.Trim(prefix, "/")
	apiPath := c.mount + "/metadata/" + logical
	if logical == "" {
		apiPath = c.mount + "/metadata"
	}

	// KV-v2 list is GET with ?list=true (equivalent to the LIST verb).
	payload, err := c.authedGet(ctx, apiPath, url.Values{"list": []string{"true"}})
	if err != nil {
		return nil, err
	}
	var lr struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &lr); err != nil {
		return nil, fmt.Errorf("kvclient: decode kv-v2 list: %w", err)
	}
	return lr.Data.Keys, nil
}

// authedGet performs an authenticated GET against an API path, logging the
// platform service in lazily on first use and exactly once more on a 403 (token
// expired / first-use after a prior login). It centralizes token caching, the
// X-Vault-Token header, and the read error mapping so ReadSecret and ListKeys
// share one transport path. It is GET-ONLY — there is no authedPost/authedPut in
// this package, which IS the structural read-only posture (§11.3).
func (c *Client) authedGet(ctx context.Context, apiPath string, query url.Values) ([]byte, error) {
	token, err := c.ensureToken(ctx, false)
	if err != nil {
		return nil, err
	}
	payload, status, err := c.rawGet(ctx, apiPath, query, token)
	if err != nil {
		return nil, err
	}
	if status == http.StatusForbidden {
		// Token may be expired/unscoped for this call — re-authenticate once.
		token, err = c.ensureToken(ctx, true)
		if err != nil {
			return nil, err
		}
		payload, status, err = c.rawGet(ctx, apiPath, query, token)
		if err != nil {
			return nil, err
		}
	}
	switch status {
	case http.StatusOK:
		return payload, nil
	case http.StatusNotFound:
		return nil, ErrSecretNotFound
	case http.StatusForbidden:
		return nil, fmt.Errorf("%w: %s", ErrPermission, vaultErrors(payload))
	default:
		return nil, fmt.Errorf("%w: status %d: %s", ErrUnexpectedStatus, status, vaultErrors(payload))
	}
}

// rawGet issues one GET with the Vault token header and returns body + status.
func (c *Client) rawGet(ctx context.Context, apiPath string, query url.Values, token string) ([]byte, int, error) {
	u, err := joinAPI(c.addr, apiPath)
	if err != nil {
		return nil, 0, err
	}
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("kvclient: build read request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("kvclient: read transport: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("kvclient: read response body: %w", err)
	}
	return payload, resp.StatusCode, nil
}

// ensureToken returns the cached Vault token, logging the platform service in
// when the cache is empty or force is set (a 403 re-auth). It serializes login
// under the mutex so concurrent reads share one login.
func (c *Client) ensureToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && !force {
		return c.token, nil
	}
	tok, err := c.auth.Login(ctx, c.doer, c.addr)
	if err != nil {
		return "", err
	}
	c.token = tok
	return tok, nil
}

// joinAPI joins a store base address and a v1 API path into an absolute URL,
// inserting the Vault "/v1/" API prefix. apiPath is the logical API path WITHOUT
// the v1 prefix (e.g. "secret/data/foo" or "auth/jwt/login").
func joinAPI(addr, apiPath string) (string, error) {
	base, err := url.Parse(strings.TrimRight(addr, "/"))
	if err != nil {
		return "", fmt.Errorf("kvclient: parse store address: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/" + strings.TrimLeft(apiPath, "/")
	return base.String(), nil
}

// vaultErrors extracts the {"errors":[...]} array Vault returns on a failure
// into a single human string for error wrapping. It never returns "" so wrapped
// errors always carry context; on an unparseable body it falls back to a bounded
// raw snippet.
func vaultErrors(payload []byte) string {
	var ve struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(payload, &ve); err == nil && len(ve.Errors) > 0 {
		return strings.Join(ve.Errors, "; ")
	}
	snippet := strings.TrimSpace(string(payload))
	if snippet == "" {
		return "(no error body)"
	}
	if len(snippet) > 256 {
		snippet = snippet[:256] + "…"
	}
	return snippet
}
