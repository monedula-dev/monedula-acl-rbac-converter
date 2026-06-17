// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

// This file exercises the credential-resolution matrix end-to-end at the
// package level — the security-sensitive area where the OS-user/MDS-user
// cache-key split and the precedence bug lived. The precedence regression
// itself is guarded by TestResolveToken_ExplicitUserRejectsMismatchedCache
// (token_test.go); the tests here cover the surrounding cells: the
// --cache-token round-trip, the error/expiry/malformed paths, and the
// exchange failure modes.

// TestResolveToken_CacheTokenRoundTripThenURLOnly is the Codex P1 flow at the
// package level: an operator authenticates with user+password and persists
// the token (what `--cache-token` does via WriteTokenCacheForOSUser), then a
// LATER invocation that supplies only --mds-url resolves the same token from
// the cache. This is exactly the sequence cli.MDSAuthFlags.ResolveClient
// performs; if the write keyed on the MDS user instead of the OS user, the
// URL-only lookup would miss and the operator would be re-prompted.
func TestResolveToken_CacheTokenRoundTripThenURLOnly(t *testing.T) {
	isolateUserConfigDir(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/security/1.0/authenticate" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"auth_token":"exchanged-then-cached","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	pwPath := filepath.Join(dir, "password")
	if err := os.WriteFile(pwPath, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Step 1: resolve via user+password (the exchange path).
	tok, err := mds.ResolveToken(mds.AuthConfig{URL: srv.URL, User: "alice", PasswordFile: pwPath})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.Token != "exchanged-then-cached" {
		t.Fatalf("exchange token: got %q", tok.Token)
	}

	// Step 1b: --cache-token persists it keyed on the OS user.
	if err := mds.WriteTokenCacheForOSUser(tok); err != nil {
		t.Fatalf("cache write: %v", err)
	}

	// Step 2: a later URL-only invocation (no user/password/token-file) must
	// discover the cached token. The MDS endpoint would 404 the lookup, so a
	// successful resolve here proves it came from the cache, not a re-exchange.
	got, err := mds.ResolveToken(mds.AuthConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("URL-only resolve after --cache-token: %v", err)
	}
	if got.Token != "exchanged-then-cached" {
		t.Errorf("URL-only resolve: got %q, want the cached token", got.Token)
	}
}

// TestResolveToken_TokenFileMissingErrors covers the token-file branch's
// read-error path: a non-existent token file must surface an error, not an
// empty token that would later authenticate as nobody.
func TestResolveToken_TokenFileMissingErrors(t *testing.T) {
	_, err := mds.ResolveToken(mds.AuthConfig{
		URL:           "https://mds.example.com",
		TokenFilePath: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if err == nil {
		t.Fatal("expected an error for a missing token file")
	}
	if !strings.Contains(err.Error(), "read token file") {
		t.Errorf("error should name the token-file read failure; got %v", err)
	}
}

// TestResolveToken_TokenFileTrimsWhitespace pins that a token file with a
// trailing newline (the common `echo $TOK > file` shape) yields the trimmed
// token — a stray newline in the Bearer header is rejected by MDS.
func TestResolveToken_TokenFileTrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("  padded-token\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := mds.ResolveToken(mds.AuthConfig{URL: "https://mds.example.com", TokenFilePath: p})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok.Token != "padded-token" {
		t.Errorf("token should be trimmed: got %q", tok.Token)
	}
}

// TestReadTokenCache_MalformedJSONErrors covers the cache decode-failure
// path: a corrupt cache file must error rather than yield a zero-value Token
// that would silently authenticate with an empty bearer.
func TestReadTokenCache_MalformedJSONErrors(t *testing.T) {
	isolateUserConfigDir(t)

	// Write a valid token first so the on-disk path exists, then clobber it
	// with garbage at the same cache path.
	tok := mds.Token{
		URL:       "https://mds.example.com",
		User:      "alice",
		Token:     "good",
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
	}
	if err := mds.WriteTokenCache(tok); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	path := expectedCachePath(t, "https://mds.example.com", "alice")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("clobber: %v", err)
	}

	if _, err := mds.ReadTokenCache("https://mds.example.com", "alice"); err == nil {
		t.Fatal("expected a decode error for malformed cache JSON")
	}
}

// TestReadTokenCache_MissingFileErrors covers the missing-file branch.
func TestReadTokenCache_MissingFileErrors(t *testing.T) {
	isolateUserConfigDir(t)
	if _, err := mds.ReadTokenCache("https://never-cached.example.com", "ghost"); err == nil {
		t.Fatal("expected an error for a cache file that was never written")
	}
}

// TestExchange_HTTPErrorSurfacesStatus covers the exchange error path where
// MDS rejects the credentials (401). The status and body must surface so the
// operator can tell a bad password from a network failure.
func TestExchange_HTTPErrorSurfacesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	pwPath := filepath.Join(dir, "password")
	if err := os.WriteFile(pwPath, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := mds.ResolveToken(mds.AuthConfig{URL: srv.URL, User: "alice", PasswordFile: pwPath})
	if err == nil {
		t.Fatal("expected an error when MDS rejects the credentials")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should surface the 401 status; got %v", err)
	}
}

// TestExchange_PasswordFileMissingErrors covers the exchange branch's
// password-file read failure (user+password supplied but the file is absent).
func TestExchange_PasswordFileMissingErrors(t *testing.T) {
	_, err := mds.ResolveToken(mds.AuthConfig{
		URL:          "https://mds.example.com",
		User:         "alice",
		PasswordFile: filepath.Join(t.TempDir(), "nope"),
	})
	if err == nil {
		t.Fatal("expected an error for a missing password file")
	}
	if !strings.Contains(err.Error(), "read password file") {
		t.Errorf("error should name the password-file read failure; got %v", err)
	}
}

// TestExchange_MalformedResponseErrors covers the decode-failure path: MDS
// returns 200 but a body that isn't the expected JSON.
func TestExchange_MalformedResponseErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	pwPath := filepath.Join(dir, "password")
	if err := os.WriteFile(pwPath, []byte("pw"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := mds.ResolveToken(mds.AuthConfig{URL: srv.URL, User: "alice", PasswordFile: pwPath})
	if err == nil {
		t.Fatal("expected a decode error for a non-JSON auth response")
	}
	if !strings.Contains(err.Error(), "decode auth response") {
		t.Errorf("error should name the decode failure; got %v", err)
	}
}

// TestExchange_ZeroExpiresInDefaultsToOneHour pins the ttl fallback: an MDS
// that returns expires_in <= 0 must not yield an already-expired token (which
// ReadTokenCache would then reject on the next read).
func TestExchange_ZeroExpiresInDefaultsToOneHour(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"auth_token":"t","token_type":"Bearer","expires_in":0}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	pwPath := filepath.Join(dir, "password")
	if err := os.WriteFile(pwPath, []byte("pw"), 0o600); err != nil {
		t.Fatal(err)
	}

	tok, err := mds.ResolveToken(mds.AuthConfig{URL: srv.URL, User: "alice", PasswordFile: pwPath})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !tok.ExpiresAt.After(time.Now().Add(30 * time.Minute)) {
		t.Errorf("expires_in<=0 should default to ~1h; got ExpiresAt=%s", tok.ExpiresAt)
	}
}
