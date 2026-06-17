// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParsePrincipalFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "principals.txt")
	content := "User:alice\n" +
		"# this is a comment\n" +
		"\n" +
		"  User:bob  \n" +
		"   \n" +
		"User:alice\n" + // duplicate
		"User:carol\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parsePrincipalFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"User:alice", "User:bob", "User:carol"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePrincipalFile_Missing(t *testing.T) {
	_, err := parsePrincipalFile(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "--principal-file") {
		t.Errorf("error should be tagged with the flag name; got %v", err)
	}
}

func TestMergePrincipals_Dedupe(t *testing.T) {
	got := mergePrincipals(
		[]string{"User:alice", "User:bob"},
		[]string{"User:bob", "User:carol", "User:alice"},
	)
	want := []string{"User:alice", "User:bob", "User:carol"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMergePrincipals_FlagFirstOrdering(t *testing.T) {
	got := mergePrincipals(
		[]string{"User:zeta", "User:alpha"},
		[]string{"User:beta"},
	)
	want := []string{"User:zeta", "User:alpha", "User:beta"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (flag values must appear before file values)", got, want)
	}
}
