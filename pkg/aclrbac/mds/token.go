// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// currentUser is a seam for tests to simulate user.Current() failing.
var currentUser = user.Current

// AuthConfig describes everything auth-resolution needs. Exactly one of
// TokenFilePath, (User + PasswordFile), or "fall back to cache" should be
// supplied; the resolver picks in that order.
type AuthConfig struct {
	URL           string
	TokenFilePath string
	User          string
	PasswordFile  string
	// Password, if non-empty, is used in preference to PasswordFile. Callers
	// that already have the cleartext (e.g. `auth login` reading the password
	// interactively) use this to avoid writing it to a temp file. On Windows
	// `os.CreateTemp` + `f.Chmod(0o600)` does NOT set Unix permissions on the
	// resulting file (it's left world-readable in the system temp dir until
	// the deferred os.Remove fires), so an in-memory hand-off is materially
	// safer than the disk round-trip. PasswordFile is still the only path
	// for `apply` / `verify` etc. (the user explicitly provided a file).
	Password           string
	CACertPath         string
	ClientCertPath     string
	ClientKeyPath      string
	InsecureSkipVerify bool
}

// Token is one cached token entry. Same on-disk format as the cache file.
type Token struct {
	URL       string    `json:"mds_url"`
	User      string    `json:"user"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
}

// ResolveToken applies the §10 resolution order:
//  1. TokenFilePath
//  2. User + PasswordFile (exchange for token)
//  3. Cache keyed on (URL, current OS user) — the single scheme written by
//     both `auth login` and `--cache-token` (spec §10.4–10.5). If the
//     operator named a specific MDS principal via --mds-user, a cached
//     token is only honored when it was issued for that same principal;
//     otherwise a token cached as a different user would be silently
//     substituted.
//  4. error
func ResolveToken(cfg AuthConfig) (Token, error) {
	if cfg.TokenFilePath != "" {
		raw, err := os.ReadFile(cfg.TokenFilePath)
		if err != nil {
			return Token{}, fmt.Errorf("read token file: %w", err)
		}
		return Token{
			URL:       cfg.URL,
			User:      cfg.User,
			Token:     strings.TrimSpace(string(raw)),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
	if cfg.User != "" && (cfg.PasswordFile != "" || cfg.Password != "") {
		return exchange(cfg)
	}
	if cfg.URL != "" {
		// Lookup on (URL, OS user). ReadTokenCache passes "" through to
		// cachePath, which resolves the current OS username — the scheme
		// both `auth login` and `--cache-token` write under (spec §10.4).
		if t, err := ReadTokenCache(cfg.URL, ""); err == nil {
			// When --mds-user was given, only honor a cached token issued
			// for that principal. Without this guard an operator who asked
			// for `--mds-user bob` could be handed a token `auth login`
			// cached for alice.
			if cfg.User == "" || t.User == cfg.User {
				return t, nil
			}
		}
	}
	return Token{}, fmt.Errorf("mds: no credentials available (use --mds-token-file, --mds-user + --mds-password-file, or `monedula-acl-rbac auth login`)")
}

func exchange(cfg AuthConfig) (Token, error) {
	// In-memory Password wins over PasswordFile so callers can keep the
	// cleartext off disk entirely (see AuthConfig.Password rationale).
	var password string
	if cfg.Password != "" {
		password = strings.TrimRight(cfg.Password, "\n\r")
	} else {
		pw, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return Token{}, fmt.Errorf("read password file: %w", err)
		}
		password = strings.TrimRight(string(pw), "\n\r")
	}

	endpoint, err := url.Parse(cfg.URL)
	if err != nil {
		return Token{}, fmt.Errorf("parse mds url: %w", err)
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/security/1.0/authenticate"

	tlsCl, err := NewClient(Config{URL: cfg.URL, CACertPath: cfg.CACertPath, ClientCertPath: cfg.ClientCertPath, ClientKeyPath: cfg.ClientKeyPath, InsecureSkipVerify: cfg.InsecureSkipVerify})
	if err != nil {
		return Token{}, err
	}

	req, _ := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	creds := cfg.User + ":" + password
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))

	resp, err := tlsCl.http.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("mds: authenticate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Cap the body included in the error: a misbehaving MDS that echoed
		// the Authorization header or the password into its 4xx body would
		// otherwise leak it into stderr and run-dir logs. 256 bytes keeps
		// useful diagnostic info (status code text, error name) while
		// truncating any reflected credential well before it surfaces.
		const maxBodySnippet = 256
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySnippet+1))
		suffix := ""
		if len(body) > maxBodySnippet {
			body = body[:maxBodySnippet]
			suffix = "...(truncated)"
		}
		return Token{}, fmt.Errorf("mds: authenticate returned %d: %s%s", resp.StatusCode, body, suffix)
	}

	var raw struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Token{}, fmt.Errorf("mds: decode auth response: %w", err)
	}
	ttl := time.Duration(raw.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	return Token{
		URL:       cfg.URL,
		User:      cfg.User,
		Token:     raw.AuthToken,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

// ReadTokenCache returns the cached Token for the given (URL, user). Returns
// an error if the cache file is missing or the token has expired.
func ReadTokenCache(rawURL, who string) (Token, error) {
	path, err := cachePath(rawURL, who)
	if err != nil {
		return Token{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Token{}, err
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return Token{}, err
	}
	if t.ExpiresAt.Before(time.Now().Add(30 * time.Second)) {
		return Token{}, fmt.Errorf("cached token at %s expired (or expires within 30s)", path)
	}
	return t, nil
}

// WriteTokenCache writes a token to the user's config dir with 0600 mode.
// The cache filename hashes (URL, t.User); pass an empty t.User to key on
// (URL, current OS user) — the scheme spec §10.4 mandates for `auth login`.
func WriteTokenCache(t Token) error {
	return writeTokenCacheAs(t, t.User)
}

// WriteTokenCacheForOSUser writes a token keyed on (URL, current OS user)
// while preserving the MDS user in the on-disk JSON. This is the
// `auth login` path: subsequent invocations on the same host pick up the
// cache from `--mds-url` alone (spec §10.5), without the operator having
// to remember which MDS principal they logged in as.
func WriteTokenCacheForOSUser(t Token) error {
	return writeTokenCacheAs(t, "")
}

func writeTokenCacheAs(t Token, who string) error {
	path, err := cachePath(t.URL, who)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func cachePath(rawURL, who string) (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	if who == "" {
		who, err = resolveCacheUser()
		if err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256([]byte(rawURL + ":" + who))
	name := hex.EncodeToString(sum[:])
	return filepath.Join(cfg, "monedula-acl-rbac", "tokens", name), nil
}

// resolveCacheUser derives the username that namespaces the token cache.
// user.Current() can fail in CGO-disabled cross-compiled binaries or odd
// container setups; fall back to the platform's username env var rather
// than silently using "" (which would collapse every user's cache to one
// shared key on a multi-tenant host). If every source is empty, return
// the original user.Current error so the failure is visible instead of
// producing a misleading cache path.
func resolveCacheUser() (string, error) {
	u, err := currentUser()
	if err == nil && u != nil && u.Username != "" {
		return u.Username, nil
	}
	var envKeys []string
	if runtime.GOOS == "windows" {
		envKeys = []string{"USERNAME"}
	} else {
		envKeys = []string{"USER", "LOGNAME"}
	}
	for _, k := range envKeys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("mds: cannot determine current user for token cache: %w", err)
	}
	return "", fmt.Errorf("mds: cannot determine current user for token cache (user.Current returned empty and no username env var set)")
}

// ErrTokenExpired is returned from token-using calls when a refresh is
// needed; callers may attempt re-authentication.
var ErrTokenExpired = errors.New("mds: token expired")
