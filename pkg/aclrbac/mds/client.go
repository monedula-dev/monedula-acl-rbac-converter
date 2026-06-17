// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package mds is the HTTP client for Confluent's Metadata Service. It owns
// auth resolution (token file / password exchange / cache), TLS configuration,
// capability detection, and the small REST surface monedula-acl-rbac uses
// (role-binding CRUD + effective-permission lookup).
package mds

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Config bundles everything NewClient needs. The caller is responsible for
// having resolved the token (or falling back to a username/password
// exchange via token.go).
type Config struct {
	URL                string
	Token              string
	CACertPath         string
	ClientCertPath     string
	ClientKeyPath      string
	InsecureSkipVerify bool
	Timeout            time.Duration // defaults to 30s

	// MaxRetries is the number of retry attempts (in addition to the
	// initial call) for transient failures. Zero means no retries; the
	// initial call is the only attempt. Negative values are normalized
	// to zero. There is no sentinel value — the CLI sets a default of 3
	// via the flag default, so library callers explicitly choose.
	MaxRetries int
	// RetryBase is the initial backoff delay for the first retry. Zero
	// means "use the package default" (100ms).
	RetryBase time.Duration
	// RetryCap is the upper bound on per-attempt backoff. Zero means
	// "use the package default" (5s).
	RetryCap time.Duration
	// RetryAfterCap is the upper bound on honoured Retry-After headers.
	// A server returning Retry-After: 99999 won't make us sleep an hour.
	// Zero means "use the package default" (60s).
	RetryAfterCap time.Duration

	// TokenSource, when set, re-resolves a bearer token. The client calls it
	// once per request that receives 401 Unauthorized (e.g. the initial token
	// expired mid-run), updates its cached token, and retries. Optional —
	// without it a 401 is returned as-is.
	TokenSource func() (string, error)
}

// Client is the configured HTTP client. Safe for concurrent use.
type Client struct {
	base *url.URL
	http *http.Client

	tokenMu     sync.Mutex // guards token across concurrent apply/verify workers
	token       string
	tokenSource func() (string, error)

	maxRetries    int
	retryBase     time.Duration
	retryCap      time.Duration
	retryAfterCap time.Duration

	// roleOpsCache memoizes role-definition lookups (role -> resourceType ->
	// allowed operations) so effective-mode verification doesn't re-fetch the
	// same role for every binding. Guarded by roleOpsMu.
	roleOpsMu    sync.Mutex
	roleOpsCache map[string]map[types.ResourceType]map[types.Operation]bool
}

// NewClient builds a configured client. Returns an error if the URL is
// malformed or the TLS material can't be loaded.
func NewClient(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("mds: URL is required")
	}
	base, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("mds: parse URL: %w", err)
	}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	httpCl := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			// Honour HTTP(S)_PROXY / NO_PROXY so MDS calls work behind a
			// corporate egress proxy (a common production deployment).
			Proxy: http.ProxyFromEnvironment,
			// Match http.DefaultTransport's connection-pool sanity so we
			// don't leak idle connections on long verify/apply runs.
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
	}
	if cfg.InsecureSkipVerify {
		log.Warn("TLS certificate validation disabled via --mds-insecure-skip-verify; do NOT use against production MDS",
			"url", cfg.URL)
	}

	maxRetries := cfg.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	retryBase := cfg.RetryBase
	if retryBase == 0 {
		retryBase = defaultRetryBase
	}
	retryCap := cfg.RetryCap
	if retryCap == 0 {
		retryCap = defaultRetryCap
	}
	retryAfterCap := cfg.RetryAfterCap
	if retryAfterCap == 0 {
		retryAfterCap = defaultRetryAfterCap
	}

	return &Client{
		base:          base,
		token:         cfg.Token,
		tokenSource:   cfg.TokenSource,
		http:          httpCl,
		maxRetries:    maxRetries,
		retryBase:     retryBase,
		retryCap:      retryCap,
		retryAfterCap: retryAfterCap,
		roleOpsCache:  map[string]map[types.ResourceType]map[types.Operation]bool{},
	}, nil
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
	}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("mds: read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("mds: CA cert at %s contained no certificates", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}
	// mTLS needs BOTH the cert and the key. Silently ignoring a half-set pair
	// would connect without a client cert and surface as an opaque 401 /
	// handshake failure from MDS; error clearly instead.
	if (cfg.ClientCertPath == "") != (cfg.ClientKeyPath == "") {
		return nil, fmt.Errorf("mds: --mds-client-cert and --mds-client-key must be set together")
	}
	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("mds: load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

// Get sends a GET request, returning the http.Response on 2xx and a typed
// error otherwise.
func (c *Client) Get(path string) (*http.Response, error) {
	return c.do(http.MethodGet, path, nil)
}

// Post sends a POST request with a JSON body.
func (c *Client) Post(path string, body interface{}) (*http.Response, error) {
	return c.do(http.MethodPost, path, body)
}

func (c *Client) do(method, path string, body interface{}) (*http.Response, error) {
	u := *c.base
	// `path` already has its segments percent-escaped by the api.go callers.
	// Assign it as RawPath (the on-the-wire form) and set Path to its decoded
	// form, so url.URL.String emits RawPath verbatim. Assigning only Path would
	// make String re-escape the '%' (turning %2C into %252C) and send requests
	// for a mangled principal/role.
	escaped := strings.TrimRight(c.base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	u.RawPath = escaped
	if decoded, err := url.PathUnescape(escaped); err == nil {
		u.Path = decoded
	} else {
		u.Path = escaped
	}

	var bodyBytes []byte
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("mds: marshal body: %w", err)
		}
		bodyBytes = data
	}

	resp, err := c.attempt(method, path, &u, bodyBytes)
	// On 401 the bearer token has likely expired mid-run. If a TokenSource is
	// configured, re-resolve the token once and retry the whole request.
	if err != nil && c.tokenSource != nil {
		var he *HTTPError
		if errors.As(err, &he) && he.StatusCode == http.StatusUnauthorized {
			if rerr := c.refreshToken(c.getToken()); rerr != nil {
				return nil, fmt.Errorf("mds: token refresh after 401: %w", rerr)
			}
			return c.attempt(method, path, &u, bodyBytes)
		}
	}
	return resp, err
}

func (c *Client) getToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.token
}

// refreshToken re-resolves the bearer token via the configured TokenSource.
// `old` is the token the caller saw fail with 401; if another concurrent
// worker already refreshed it (current token differs from old), this is a
// no-op so the workers don't stampede the token endpoint.
func (c *Client) refreshToken(old string) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token != old {
		return nil
	}
	if c.tokenSource == nil {
		return ErrTokenExpired
	}
	tok, err := c.tokenSource()
	if err != nil {
		return err
	}
	c.token = tok
	return nil
}

func (c *Client) attempt(method, path string, u *url.URL, bodyBytes []byte) (*http.Response, error) {
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		var reader io.Reader
		if bodyBytes != nil {
			reader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(method, u.String(), reader)
		if err != nil {
			return nil, fmt.Errorf("mds: build request: %w", err)
		}
		if tok := c.getToken(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, doErr := c.http.Do(req)
		retry, hint := shouldRetry(resp, doErr)
		if !retry || attempt == c.maxRetries {
			if doErr != nil {
				return nil, fmt.Errorf("mds: %s %s: %w", method, path, doErr)
			}
			if resp.StatusCode >= 400 {
				return nil, newHTTPError(resp)
			}
			return resp, nil
		}

		// Drain/close the body so the connection can be reused.
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		var delay time.Duration
		if hint > 0 {
			delay = hint
			if delay > c.retryAfterCap {
				delay = c.retryAfterCap
			}
		} else {
			delay = backoffDelay(attempt+1, c.retryBase, c.retryCap)
		}

		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		errStr := ""
		if doErr != nil {
			errStr = doErr.Error()
		}
		log.Warn("mds: transient failure; retrying",
			"method", method,
			"path", path,
			"attempt", attempt+1,
			"max_retries", c.maxRetries,
			"status", status,
			"err", errStr,
			"delay", delay,
		)
		time.Sleep(delay)
	}
	return nil, fmt.Errorf("mds: %s %s: exhausted %d retries", method, path, c.maxRetries)
}

// HTTPError carries the response code and body for failed requests.
type HTTPError struct {
	StatusCode int
	URL        string
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("mds: %s returned %d: %s", e.URL, e.StatusCode, e.Body)
}

// IsAuthError reports whether err is a 401/403 from MDS.
func IsAuthError(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false
	}
	return he.StatusCode == 401 || he.StatusCode == 403
}

// maxErrorBodySnippet caps the response body we capture in HTTPError. The
// captured body surfaces in three places we don't want unbounded growth or
// reflected credentials in:
//   - operator stderr (every CLI command prints the error)
//   - verify.json on disk (effective-mode probes copy err.Error() into
//     each result's `detail` field; an MDS that echoed Authorization or
//     session-cookie state into a 4xx body would persist it)
//   - apply.log (the per-call audit trail)
//
// 4 KiB is generous enough to keep useful JSON error envelopes intact (a
// typical Confluent error doc is ~200-800 B) while bounding memory if MDS
// returns a multi-MB error body, and well short of any credential a
// misbehaving server might echo. The auth-token exchange in token.go
// uses a tighter 256 B cap because that code path runs with the password
// in scope; here we are post-auth but still defence-in-depth.
const maxErrorBodySnippet = 4 * 1024

func newHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySnippet+1))
	resp.Body.Close()
	suffix := ""
	if len(body) > maxErrorBodySnippet {
		body = body[:maxErrorBodySnippet]
		suffix = "...(truncated)"
	}
	return &HTTPError{
		StatusCode: resp.StatusCode,
		URL:        resp.Request.URL.String(),
		Body:       string(body) + suffix,
	}
}
