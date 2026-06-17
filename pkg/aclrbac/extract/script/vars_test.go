// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/script"
)

// TestLoadVars_EmptyPath: an empty --vars path is the common case (no vars
// file). It must be (nil, nil), not an error.
func TestLoadVars_EmptyPath(t *testing.T) {
	m, err := script.LoadVars("")
	if err != nil {
		t.Fatalf("empty path must not error; got: %v", err)
	}
	if m != nil {
		t.Errorf("empty path must return nil map; got %v", m)
	}
}

// TestLoadVars_Loads reads a vars.yaml and returns the key/value map.
func TestLoadVars_Loads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vars.yaml")
	if err := os.WriteFile(p, []byte("TOPIC: orders\nENV: prod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := script.LoadVars(p)
	if err != nil {
		t.Fatalf("LoadVars: %v", err)
	}
	if m["TOPIC"] != "orders" || m["ENV"] != "prod" {
		t.Errorf("loaded map wrong: %v", m)
	}
}

// TestLoadVars_LoadedVarsSubstitute is the end-to-end binding: the map
// LoadVars returns must actually drive script.New's $VAR substitution. A
// LoadVars that parsed but returned the wrong shape would pass a unit map
// check yet break the only thing --vars is for.
func TestLoadVars_LoadedVarsSubstitute(t *testing.T) {
	dir := t.TempDir()
	varsPath := filepath.Join(dir, "vars.yaml")
	if err := os.WriteFile(varsPath, []byte("TOPIC: payments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(dir, "acls.sh")
	body := `kafka-acls --add --allow-principal User:bob --operation Read --topic "$TOPIC"` + "\n"
	if err := os.WriteFile(scriptPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	vars, err := script.LoadVars(varsPath)
	if err != nil {
		t.Fatalf("LoadVars: %v", err)
	}
	a, _ := script.New(scriptPath, vars, false)
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract with loaded vars: %v", err)
	}
	if set.ACLs[0].ResourceName != "payments" {
		t.Errorf("loaded var did not substitute into topic; got %q", set.ACLs[0].ResourceName)
	}
}

// TestLoadVars_MissingFileErrors: a configured but unreadable vars path is
// an error (operator typo'd the path), not a silent empty map that would
// leave $VARs unresolved with a confusing downstream failure.
func TestLoadVars_MissingFileErrors(t *testing.T) {
	_, err := script.LoadVars(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for a missing vars file")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("error should name the read failure; got: %v", err)
	}
}

// TestLoadVars_MalformedErrors: a vars file that isn't a string->string map
// must error rather than yielding a partial/garbage map.
func TestLoadVars_MalformedErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vars.yaml")
	// A YAML sequence, not a mapping -> cannot unmarshal into map[string]string.
	if err := os.WriteFile(p, []byte("- just\n- a\n- list\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := script.LoadVars(p); err == nil {
		t.Fatal("expected parse error for non-map vars file")
	}
}
