// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
)

// expectedCachePath replicates the cachePath logic from token.go so tests can
// find and clean up the file without exporting the internal function.
func expectedCachePath(t *testing.T, rawURL, who string) string {
	t.Helper()
	cfg, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir: %v", err)
	}
	sum := sha256.Sum256([]byte(rawURL + ":" + who))
	name := hex.EncodeToString(sum[:])
	return filepath.Join(cfg, "monedula-acl-rbac", "tokens", name)
}

// TestTokenCache_WriteAndRead verifies that WriteTokenCache persists a token
// that ReadTokenCache can retrieve, and that the on-disk file is mode 0600
// (POSIX only; Windows does not enforce POSIX permissions).
func TestTokenCache_WriteAndRead(t *testing.T) {
	// Use a unique URL per test run to avoid colliding with a real cached token.
	rawURL := fmt.Sprintf("https://mds.test.example.com/%d", time.Now().UnixNano())
	who := "test-user-cache-round-trip"

	tok := mds.Token{
		URL:       rawURL,
		User:      who,
		Token:     "synthetic-test-token",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), // well in the future
	}

	// Clean up after the test regardless of outcome.
	path := expectedCachePath(t, rawURL, who)
	t.Cleanup(func() { os.Remove(path) })

	if err := mds.WriteTokenCache(tok); err != nil {
		t.Fatalf("WriteTokenCache: %v", err)
	}

	// On POSIX systems, verify 0600 permissions. Windows reports 0666 for
	// files regardless of the mode passed to WriteFile.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat cache file: %v", err)
		}
		got := info.Mode().Perm()
		if got != 0o600 {
			t.Errorf("cache file mode: got %04o, want 0600", got)
		}
	}

	got, err := mds.ReadTokenCache(rawURL, who)
	if err != nil {
		t.Fatalf("ReadTokenCache: %v", err)
	}
	if got.Token != tok.Token {
		t.Errorf("token round-trip: got %q, want %q", got.Token, tok.Token)
	}
	if got.User != tok.User {
		t.Errorf("user round-trip: got %q, want %q", got.User, tok.User)
	}
	if got.URL != tok.URL {
		t.Errorf("url round-trip: got %q, want %q", got.URL, tok.URL)
	}
}

// TestTokenCache_ExpiredTokenRejected writes a token whose ExpiresAt is well
// in the past and asserts that ReadTokenCache returns an error (the
// implementation rejects tokens expiring within 30 s of now).
func TestTokenCache_ExpiredTokenRejected(t *testing.T) {
	rawURL := fmt.Sprintf("https://mds.test.example.com/expired/%d", time.Now().UnixNano())
	who := "test-user-cache-expired"

	tok := mds.Token{
		URL:       rawURL,
		User:      who,
		Token:     "expired-token",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
	}

	path := expectedCachePath(t, rawURL, who)
	t.Cleanup(func() { os.Remove(path) })

	if err := mds.WriteTokenCache(tok); err != nil {
		t.Fatalf("WriteTokenCache: %v", err)
	}

	_, err := mds.ReadTokenCache(rawURL, who)
	if err == nil {
		t.Fatal("ReadTokenCache should return an error for an expired token; got nil")
	}
	// The error should not be a missing-file error — the file exists but the
	// token is expired.
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadTokenCache returned ErrNotExist; expected an expiry error")
	}
}
