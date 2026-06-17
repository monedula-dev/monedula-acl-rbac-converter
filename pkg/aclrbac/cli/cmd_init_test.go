// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

func TestInit_CreatesScopesAndRules(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "my-run")

	exit := cli.Execute([]string{"init", target})
	if exit != 0 {
		t.Fatalf("init exit %d", exit)
	}

	for _, name := range []string{"scopes.yaml", "rules.yaml"} {
		path := filepath.Join(target, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("expected %s to exist; got %v", path, err)
			continue
		}
		if !strings.Contains(string(data), "#") {
			t.Errorf("%s should contain comments explaining the placeholders", name)
		}
	}
}

func TestInit_RefusesExistingDirWithFiles(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "my-run")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "scopes.yaml"), []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{"init", target})
	if exit == 0 {
		t.Fatal("init should refuse to overwrite existing files (exit 0 means it overwrote)")
	}

	// Confirm we didn't actually overwrite.
	data, _ := os.ReadFile(filepath.Join(target, "scopes.yaml"))
	if string(data) != "existing\n" {
		t.Errorf("scopes.yaml was overwritten; want unchanged 'existing\\n', got %q", data)
	}
}

func TestInit_DefaultToCurrentDir(t *testing.T) {
	tmp := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{"init"})
	if exit != 0 {
		t.Fatalf("init exit %d", exit)
	}
	if _, err := os.Stat(filepath.Join(tmp, "scopes.yaml")); err != nil {
		t.Errorf("expected scopes.yaml in cwd; got %v", err)
	}
}
