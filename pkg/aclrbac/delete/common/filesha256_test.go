// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
)

// TestFileSHA256_KnownVector pins the exact hash format (lowercase hex
// SHA-256 of the raw file bytes). FileSHA256 feeds the plan.sha256
// safety-contract value baked into delete-*.sh and the verify<->plan
// binding (TESTING.md §2.2 cross-file binding); a format drift here — say
// uppercase, or hashing a trimmed/normalised string — would silently make
// the runtime guard never match. The vector is the well-known SHA-256 of
// "abc".
func TestFileSHA256_KnownVector(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	p := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := common.FileSHA256(p)
	if err != nil {
		t.Fatalf("FileSHA256: %v", err)
	}
	if got != want {
		t.Errorf("FileSHA256(\"abc\") = %q, want %q", got, want)
	}
}

// TestFileSHA256_EmptyPath: an empty path is the optional-artefact sentinel
// (e.g. verify.json for rollback scripts) and must be ("", nil), not an
// error.
func TestFileSHA256_EmptyPath(t *testing.T) {
	got, err := common.FileSHA256("")
	if err != nil {
		t.Fatalf("empty path must not error; got: %v", err)
	}
	if got != "" {
		t.Errorf("empty path must hash to \"\"; got %q", got)
	}
}

// TestFileSHA256_MissingFileErrors: a non-empty path that can't be read is
// an error, never a silent "" that would let the script's plan.sha256 guard
// be generated empty and mismatch at runtime.
func TestFileSHA256_MissingFileErrors(t *testing.T) {
	_, err := common.FileSHA256(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("expected error for a missing file")
	}
}

// TestVerifyACLsSHA pins the integrity gate: a plan stamped with an
// acls.json SHA refuses when the file no longer matches, accepts when it
// does, and is a no-op for an unstamped (empty) plan.
func TestVerifyACLsSHA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acls.json")
	if err := os.WriteFile(path, []byte(`{"acls":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := common.FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := common.VerifyACLsSHA(sum, path); err != nil {
		t.Errorf("matching SHA should pass: %v", err)
	}
	if err := common.VerifyACLsSHA("", path); err != nil {
		t.Errorf("empty (unstamped) plan SHA must be a no-op: %v", err)
	}
	if err := common.VerifyACLsSHA("deadbeef", path); err == nil {
		t.Error("mismatched SHA must be refused")
	}
}
