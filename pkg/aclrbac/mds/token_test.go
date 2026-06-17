// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

func TestResolveToken_TokenFileWins(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("pre-fetched-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	tok, err := mds.ResolveToken(mds.AuthConfig{
		URL:           "https://mds.example.com",
		TokenFilePath: tokenPath,
		User:          "alice",
		PasswordFile:  "/should/not/be/read",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok.Token != "pre-fetched-token" {
		t.Errorf("token-file should win: got %q", tok.Token)
	}
}

func TestResolveToken_UserPasswordExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/security/1.0/authenticate" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth_token": "fresh-token-abc",
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	pwPath := filepath.Join(dir, "password")
	if err := os.WriteFile(pwPath, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tok, err := mds.ResolveToken(mds.AuthConfig{
		URL:          srv.URL,
		User:         "alice",
		PasswordFile: pwPath,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok.Token != "fresh-token-abc" {
		t.Errorf("token: got %q", tok.Token)
	}
	if tok.ExpiresAt.Before(time.Now()) {
		t.Errorf("expires_at should be in the future")
	}
}

func TestCacheRoundTrip(t *testing.T) {
	isolateUserConfigDir(t)

	tok := mds.Token{
		URL:       "https://mds.example.com",
		User:      "alice",
		Token:     "abc",
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
	}
	if err := mds.WriteTokenCache(tok); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := mds.ReadTokenCache("https://mds.example.com", "alice")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Token != "abc" {
		t.Errorf("cache: got %q", got.Token)
	}
}

func TestReadTokenCache_ExpiredReturnsNotFound(t *testing.T) {
	isolateUserConfigDir(t)

	tok := mds.Token{
		URL:       "https://mds.example.com",
		User:      "alice",
		Token:     "expired",
		ExpiresAt: time.Now().Add(-time.Hour),
		IssuedAt:  time.Now().Add(-2 * time.Hour),
	}
	_ = mds.WriteTokenCache(tok)

	_, err := mds.ReadTokenCache("https://mds.example.com", "alice")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

// TestResolveToken_URLOnlyCacheDiscovery exercises the README:371-374 flow:
// after `auth login` has written the cache, a subsequent `apply --mds-url X`
// without --mds-user must resolve the cached token via (URL, OS user) per
// spec §10.5.
func TestResolveToken_URLOnlyCacheDiscovery(t *testing.T) {
	isolateUserConfigDir(t)

	tok := mds.Token{
		URL:       "https://mds.example.com",
		User:      "alice", // MDS user — recorded in content, not in the cache key
		Token:     "url-only-discovery-token",
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
	}
	// This is what `auth login` does: write keyed on OS user.
	if err := mds.WriteTokenCacheForOSUser(tok); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Caller passes only --mds-url; no --mds-user, no --mds-token-file,
	// no --mds-password-file. Per spec §10.5 the cache should be found.
	got, err := mds.ResolveToken(mds.AuthConfig{URL: "https://mds.example.com"})
	if err != nil {
		t.Fatalf("ResolveToken with --mds-url alone: %v", err)
	}
	if got.Token != "url-only-discovery-token" {
		t.Errorf("expected cached token, got %q", got.Token)
	}
}

// TestResolveToken_NoCredentialsErrorPath asserts that ResolveToken returns
// the "no credentials" error when neither a cache nor any credential flag
// is available, even on the URL-only auto-discovery path.
func TestResolveToken_NoCredentialsErrorPath(t *testing.T) {
	isolateUserConfigDir(t)

	_, err := mds.ResolveToken(mds.AuthConfig{URL: "https://no-cache.example.com"})
	if err == nil {
		t.Fatal("expected an error when no cache and no credentials are available")
	}
}

// TestResolveToken_ExplicitUserRejectsMismatchedCache guards the precedence
// fix: a token cached (OS-user keyed) for principal "alice" must NOT be
// returned when the operator explicitly asks for "--mds-user bob". Otherwise
// ResolveToken would silently hand back alice's token for a bob request.
func TestResolveToken_ExplicitUserRejectsMismatchedCache(t *testing.T) {
	isolateUserConfigDir(t)

	tok := mds.Token{
		URL:       "https://mds.example.com",
		User:      "alice",
		Token:     "alice-token",
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
	}
	if err := mds.WriteTokenCacheForOSUser(tok); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Operator names bob and supplies no other credential — the alice cache
	// must be rejected, surfacing the "no credentials" error rather than
	// alice's token.
	_, err := mds.ResolveToken(mds.AuthConfig{URL: "https://mds.example.com", User: "bob"})
	if err == nil {
		t.Fatal("expected refusal: cached token is for a different MDS principal")
	}

	// Sanity: the matching principal still resolves.
	got, err := mds.ResolveToken(mds.AuthConfig{URL: "https://mds.example.com", User: "alice"})
	if err != nil {
		t.Fatalf("matching principal should resolve: %v", err)
	}
	if got.Token != "alice-token" {
		t.Errorf("expected alice-token, got %q", got.Token)
	}
}

// isolateUserConfigDir points os.UserConfigDir() at a per-test temp directory
// on every supported platform. Without this, tests that write to the cache
// would leak files into the developer's real ~/.config or %AppData% and
// could be picked up by other tests (or production invocations) on the same
// machine.
func isolateUserConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	// Linux / *BSD
	t.Setenv("XDG_CONFIG_HOME", dir)
	// Darwin (returns $HOME/Library/Application Support)
	t.Setenv("HOME", dir)
	// Windows (returns %AppData%)
	t.Setenv("AppData", dir)
}
