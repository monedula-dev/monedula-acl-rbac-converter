// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package mds

import (
	"errors"
	"os/user"
	"runtime"
	"strings"
	"testing"
)

// TestCachePath_UserCurrentFailsFallsBackToEnv is the B16 regression
// guard: when user.Current() errors, cachePath must fall back to the
// platform username env var rather than silently namespacing the cache
// under an empty user (which would collapse every account's cache to one
// shared key on a multi-tenant host).
func TestCachePath_UserCurrentFailsFallsBackToEnv(t *testing.T) {
	orig := currentUser
	currentUser = func() (*user.User, error) { return nil, errors.New("boom") }
	defer func() { currentUser = orig }()

	var key string
	if runtime.GOOS == "windows" {
		key = "USERNAME"
	} else {
		key = "USER"
	}
	t.Setenv(key, "fallback-user")
	// Clear LOGNAME on unix so USER is the one that wins (deterministic).
	if runtime.GOOS != "windows" {
		t.Setenv("LOGNAME", "")
	}

	got, err := resolveCacheUser()
	if err != nil {
		t.Fatalf("expected env fallback, got error: %v", err)
	}
	if got != "fallback-user" {
		t.Errorf("resolveCacheUser = %q, want %q", got, "fallback-user")
	}

	// cachePath must succeed and incorporate the fallback user.
	p, err := cachePath("https://mds.example.com", "")
	if err != nil {
		t.Fatalf("cachePath: %v", err)
	}
	if strings.TrimSpace(p) == "" {
		t.Error("cachePath returned empty path")
	}
}

// TestCachePath_UserCurrentFailsNoEnvErrors asserts that when both
// user.Current() fails AND no username env var is set, cachePath returns
// an error rather than silently using "".
func TestCachePath_UserCurrentFailsNoEnvErrors(t *testing.T) {
	orig := currentUser
	currentUser = func() (*user.User, error) { return nil, errors.New("boom") }
	defer func() { currentUser = orig }()

	// Blank every username source.
	for _, k := range []string{"USER", "LOGNAME", "USERNAME"} {
		t.Setenv(k, "")
	}

	if _, err := resolveCacheUser(); err == nil {
		t.Fatal("expected error when no user source is available")
	}
	if _, err := cachePath("https://mds.example.com", ""); err == nil {
		t.Fatal("cachePath should propagate the no-user error")
	}
}

// TestCachePath_ExplicitWhoBypassesLookup confirms passing a non-empty
// `who` skips user.Current entirely (the delete-deny-one path supplies it).
func TestCachePath_ExplicitWhoBypassesLookup(t *testing.T) {
	orig := currentUser
	currentUser = func() (*user.User, error) {
		t.Fatal("user.Current must not be called when who is supplied")
		return nil, nil
	}
	defer func() { currentUser = orig }()

	if _, err := cachePath("https://mds.example.com", "explicit"); err != nil {
		t.Fatalf("cachePath with explicit who: %v", err)
	}
}
