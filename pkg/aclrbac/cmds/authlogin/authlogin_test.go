// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package authlogin_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/authlogin"
)

func TestRun_InteractiveExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"auth_token":"fresh-tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	// Isolate os.UserConfigDir on every platform so the test does not
	// leak a cache file into the developer's real config dir.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir) // Linux / *BSD
	t.Setenv("HOME", dir)            // Darwin
	t.Setenv("AppData", dir)         // Windows

	in := strings.NewReader("alice\n")
	var out bytes.Buffer

	if err := authlogin.Run(authlogin.Options{
		URL:            srv.URL,
		Stdin:          in,
		Stdout:         &out,
		PasswordReader: func() (string, error) { return "hunter2", nil },
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "Cached token") {
		t.Errorf("expected success message:\n%s", out.String())
	}
}

// isolateConfigDir points os.UserConfigDir at a temp dir on every platform so
// the cache-write path doesn't leak into the developer's real config dir.
func isolateConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir) // Linux / *BSD
	t.Setenv("HOME", dir)            // Darwin
	t.Setenv("AppData", dir)         // Windows
}

// TestRun_EmptyUsernameRejected covers the early-exit guard: a blank MDS user
// must error before any network call or cache write, so an operator who just
// hits Enter doesn't silently cache an empty-principal token.
func TestRun_EmptyUsernameRejected(t *testing.T) {
	var out bytes.Buffer
	err := authlogin.Run(authlogin.Options{
		URL:            "https://mds.example.com",
		Stdin:          strings.NewReader("   \n"), // whitespace-only username
		Stdout:         &out,
		PasswordReader: func() (string, error) { return "pw", nil },
	})
	if err == nil {
		t.Fatal("expected an error for an empty username")
	}
	if !strings.Contains(err.Error(), "empty username") {
		t.Errorf("error should name the empty username; got %v", err)
	}
}

// TestRun_StdinEOFErrors covers the ReadString error path: stdin closed
// before any line is read (no trailing newline / empty reader) must surface
// the read error rather than proceeding with a partial username.
func TestRun_StdinEOFErrors(t *testing.T) {
	var out bytes.Buffer
	err := authlogin.Run(authlogin.Options{
		URL:            "https://mds.example.com",
		Stdin:          strings.NewReader(""), // immediate EOF
		Stdout:         &out,
		PasswordReader: func() (string, error) { return "pw", nil },
	})
	if err == nil {
		t.Fatal("expected an error when stdin yields no username line")
	}
}

// TestRun_PasswordReaderError covers the password-prompt failure path: a
// PasswordReader that errors (e.g. a closed TTY) must abort the login rather
// than exchanging with an empty password.
func TestRun_PasswordReaderError(t *testing.T) {
	var out bytes.Buffer
	err := authlogin.Run(authlogin.Options{
		URL:            "https://mds.example.com",
		Stdin:          strings.NewReader("alice\n"),
		Stdout:         &out,
		PasswordReader: func() (string, error) { return "", errPasswordPrompt },
	})
	if err == nil {
		t.Fatal("expected an error when the password reader fails")
	}
}

var errPasswordPrompt = errPrompt("password prompt failed")

type errPrompt string

func (e errPrompt) Error() string { return string(e) }

// TestRun_ExchangeFailurePropagates covers the ResolveToken-error path: when
// MDS rejects the credentials, Run must return the error and write no cache.
func TestRun_ExchangeFailurePropagates(t *testing.T) {
	isolateConfigDir(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}))
	defer srv.Close()

	var out bytes.Buffer
	err := authlogin.Run(authlogin.Options{
		URL:            srv.URL,
		Stdin:          strings.NewReader("alice\n"),
		Stdout:         &out,
		PasswordReader: func() (string, error) { return "wrong", nil },
	})
	if err == nil {
		t.Fatal("expected an error when MDS rejects the credentials")
	}
	if strings.Contains(out.String(), "Cached token") {
		t.Errorf("must not report a cached token on exchange failure:\n%s", out.String())
	}
}

// TestRun_NilPasswordReaderUsesTerm covers the default password-prompt
// branch (PasswordReader == nil -> term.ReadPassword on os.Stdin). Under the
// test harness os.Stdin is not a TTY, so term.ReadPassword returns an error,
// which Run must propagate. This exercises the otherwise-untested term branch
// without requiring a real terminal; the username still comes from opts.Stdin.
func TestRun_NilPasswordReaderUsesTerm(t *testing.T) {
	var out bytes.Buffer
	err := authlogin.Run(authlogin.Options{
		URL:    "https://mds.example.com",
		Stdin:  strings.NewReader("alice\n"),
		Stdout: &out,
		// PasswordReader nil on purpose -> falls through to term.ReadPassword.
	})
	if err == nil {
		t.Fatal("expected an error: term.ReadPassword on a non-TTY stdin should fail")
	}
	if strings.Contains(out.String(), "Cached token") {
		t.Errorf("must not report success when the password prompt failed:\n%s", out.String())
	}
}

// TestRun_CacheWriteFailurePropagates covers the WriteTokenCacheForOSUser
// error branch: the exchange succeeds but the cache dir cannot be created, so
// Run must return that error and NOT print the "Cached token" success line.
// We force the failure by pointing the user config dir at a regular file, so
// MkdirAll(filepath.Dir(cachePath)) fails on every platform.
func TestRun_CacheWriteFailurePropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"auth_token":"t","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	// Create a file and point the per-platform config-dir env vars at it.
	// os.UserConfigDir then returns this file path; the token cache lives at
	// <configdir>/monedula-acl-rbac/tokens/<hash>, so MkdirAll of its parent
	// fails because a path component is a file, not a directory.
	base := t.TempDir()
	notADir := filepath.Join(base, "config-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", notADir) // Linux / *BSD
	t.Setenv("HOME", notADir)            // Darwin (-> notADir/Library/Application Support)
	t.Setenv("AppData", notADir)         // Windows

	var out bytes.Buffer
	err := authlogin.Run(authlogin.Options{
		URL:            srv.URL,
		Stdin:          strings.NewReader("alice\n"),
		Stdout:         &out,
		PasswordReader: func() (string, error) { return "pw", nil },
	})
	if err == nil {
		t.Fatal("expected an error when the token cache cannot be written")
	}
	if strings.Contains(out.String(), "Cached token") {
		t.Errorf("must not report success when the cache write failed:\n%s", out.String())
	}
}
