// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestPlan_CFKNameSaltChangesBindingID asserts that the same ACLs run
// through `plan` with and without --cfk-name-salt produce different
// Binding.IDs, and that the same salt produces the same ID across runs.
func TestPlan_CFKNameSaltChangesBindingID(t *testing.T) {
	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")

	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	readID := func(planPath string) string {
		t.Helper()
		data, err := os.ReadFile(planPath)
		if err != nil {
			t.Fatalf("read plan: %v", err)
		}
		var p types.Plan
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("decode plan: %v", err)
		}
		if len(p.Bindings) != 1 {
			t.Fatalf("got %d bindings, want 1", len(p.Bindings))
		}
		return p.Bindings[0].ID
	}

	// Run #1: no salt.
	noSaltPath := filepath.Join(tmp, "plan-nosalt.json")
	if exit := cli.Execute([]string{
		"plan", "--acls", aclsPath, "--scopes", scopesPath, "--out", noSaltPath,
	}); exit != 0 {
		t.Fatalf("plan #1 exit %d", exit)
	}
	noSaltID := readID(noSaltPath)

	// Run #2: with salt "tenant-A".
	saltedPath := filepath.Join(tmp, "plan-salted.json")
	if exit := cli.Execute([]string{
		"plan", "--acls", aclsPath, "--scopes", scopesPath,
		"--cfk-name-salt", "tenant-A",
		"--out", saltedPath,
	}); exit != 0 {
		t.Fatalf("plan #2 exit %d", exit)
	}
	saltedID := readID(saltedPath)

	if noSaltID == saltedID {
		t.Errorf("salted ID should differ from unsalted; both = %q", noSaltID)
	}

	// Run #3: same salt again — deterministic.
	saltedPath2 := filepath.Join(tmp, "plan-salted2.json")
	if exit := cli.Execute([]string{
		"plan", "--acls", aclsPath, "--scopes", scopesPath,
		"--cfk-name-salt", "tenant-A",
		"--out", saltedPath2,
	}); exit != 0 {
		t.Fatalf("plan #3 exit %d", exit)
	}
	if got := readID(saltedPath2); got != saltedID {
		t.Errorf("same salt should be deterministic; got %q vs %q", got, saltedID)
	}

	// Sanity: IDs always start with "rb-" and have the right length.
	if !strings.HasPrefix(noSaltID, "rb-") || len(noSaltID) != 15 {
		t.Errorf("malformed ID: %q", noSaltID)
	}
}

// TestConvert_ScriptWithVars exercises `convert --from script --vars` to
// confirm the variable substitution path is reachable from convert (not
// just from `extract --from script`).
func TestConvert_ScriptWithVars(t *testing.T) {
	tmp := t.TempDir()
	scriptPath := filepath.Join(tmp, "add.sh")
	varsPath := filepath.Join(tmp, "vars.yaml")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	outPath := filepath.Join(tmp, "out.sh")

	// Read+Describe maps to DeveloperRead per the default rules, so the
	// plan produces a binding whose emitted script references "orders".
	// That keeps the test sensitive to the variable actually being
	// substituted — if $TOPIC weren't expanded, extract would have
	// errored out long before we got here.
	const body = `kafka-acls --add --allow-principal User:alice --operation Read --operation Describe --topic "$TOPIC"` + "\n"
	if err := os.WriteFile(scriptPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(varsPath, []byte("TOPIC: orders\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{
		"convert",
		"--from", "script",
		"--input", scriptPath,
		"--vars", varsPath,
		"--scopes", scopesPath,
		"--format", "script",
		"--out", outPath,
	})
	if exit != 0 {
		t.Fatalf("convert exit %d (expected success after vars wired)", exit)
	}

	// The emitted artifact should reference the resolved topic "orders" —
	// proving the variable substitution actually ran end-to-end.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "orders") {
		t.Errorf("output should contain resolved topic name 'orders'; got:\n%s", data)
	}
}

// TestConvert_CFKNamespace asserts that --cfk-namespace flows into the
// emitted CFK manifest's metadata.namespace.
func TestConvert_CFKNamespace(t *testing.T) {
	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	outPath := filepath.Join(tmp, "out.yaml")

	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{
		"convert",
		"--from", "json",
		"--input", aclsPath,
		"--scopes", scopesPath,
		"--format", "cfk",
		"--cfk-namespace", "tenant-a",
		"--out", outPath,
	})
	if exit != 0 {
		t.Fatalf("convert exit %d", exit)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "namespace: tenant-a") {
		t.Errorf("emitted CFK should have namespace: tenant-a; got:\n%s", data)
	}
}

// TestConvert_FormatFlag_NoDeprecation asserts that --format (the new
// primary flag) works and does NOT emit a deprecation warning.
func TestConvert_FormatFlag_NoDeprecation(t *testing.T) {
	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	outPath := filepath.Join(tmp, "out.sh")

	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		exit := cli.Execute([]string{
			"convert",
			"--from", "json",
			"--input", aclsPath,
			"--scopes", scopesPath,
			"--format", "script",
			"--out", outPath,
		})
		if exit != 0 {
			t.Fatalf("convert with --format exit %d", exit)
		}
	})
	if strings.Contains(strings.ToLower(stderr), "deprecat") {
		t.Errorf("--format is the primary flag; should not emit deprecation:\n%s", stderr)
	}
}
