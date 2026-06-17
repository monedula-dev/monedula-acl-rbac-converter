// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package convert_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/convert"
)

// minimalACLSetYAML is a self-contained ACL set with one Read+Describe Topic
// pair that the default rules map to DeveloperRead.
const minimalACLSetYAML = `schema_version: "1"
source:
  type: yaml
  generated_at: "2026-05-21T10:00:00Z"
acls:
  - id: 1
    principal: "User:alice"
    host: "*"
    operation: Read
    resource_type: Topic
    resource_name: orders
    pattern_type: LITERAL
    permission_type: Allow
  - id: 2
    principal: "User:alice"
    host: "*"
    operation: Describe
    resource_type: Topic
    resource_name: orders
    pattern_type: LITERAL
    permission_type: Allow
`

const minimalACLSetJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-21T10:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`

const minimalACLSetCSV = `id,principal,host,operation,resource_type,resource_name,pattern_type,permission_type
1,User:alice,*,Read,Topic,orders,LITERAL,Allow
2,User:alice,*,Describe,Topic,orders,LITERAL,Allow
`

// minimalACLSetText uses kafka-acls.sh --list format
// (regex: resourceType=..., name=..., patternType=...).
const minimalACLSetText = `Current ACLs for resource ` + "`" + `ResourcePattern(resourceType=TOPIC, name=orders, patternType=LITERAL)` + "`" + `:
	(principal=User:alice, host=*, operation=READ, permissionType=ALLOW)
	(principal=User:alice, host=*, operation=DESCRIBE, permissionType=ALLOW)
`

const scopesYAML = "kafka_cluster: lkc-kafka01\n"

// writeFixtures writes all needed files and returns the dir.
func writeFixtures(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// ---- from-format tests ------------------------------------------------------

func TestRun_FromJSON(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.json":   minimalACLSetJSON,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		From:       "json",
		InputPath:  filepath.Join(dir, "acls.json"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("expected DeveloperRead in output:\n%s", buf.String())
	}
}

func TestRun_FromCSV(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.csv":    minimalACLSetCSV,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		From:       "csv",
		InputPath:  filepath.Join(dir, "acls.csv"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("expected DeveloperRead in output:\n%s", buf.String())
	}
}

func TestRun_FromText(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.txt":    minimalACLSetText,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		From:       "text",
		InputPath:  filepath.Join(dir, "acls.txt"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("expected DeveloperRead in output:\n%s", buf.String())
	}
}

func TestRun_FromYAML_ExplicitFlag(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		From:       "yaml",
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("expected DeveloperRead in output:\n%s", buf.String())
	}
}

func TestRun_InvalidFrom_ReturnsError(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		From:       "nosuchformat",
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err == nil {
		t.Fatal("expected error for invalid --from, got nil")
	}
	if !strings.Contains(err.Error(), "nosuchformat") {
		t.Errorf("error should mention the bad --from value: %v", err)
	}
}

func TestRun_LiveFrom_ReturnsDescriptiveError(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		From:       "live",
		InputPath:  filepath.Join(dir, "dummy"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err == nil {
		t.Fatal("expected error for --from live, got nil")
	}
	if !strings.Contains(err.Error(), "stateless") {
		t.Errorf("error should mention stateless constraint: %v", err)
	}
}

// ---- auto-detect from extension --------------------------------------------

func TestRun_AutoDetect_YAMLExtension(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("expected DeveloperRead in auto-detected YAML output:\n%s", buf.String())
	}
}

func TestRun_AutoDetect_JSONExtension(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.json":   minimalACLSetJSON,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.json"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("expected DeveloperRead in auto-detected JSON output:\n%s", buf.String())
	}
}

func TestRun_AutoDetect_CSVExtension(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.csv":    minimalACLSetCSV,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.csv"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("expected DeveloperRead in auto-detected CSV output:\n%s", buf.String())
	}
}

func TestRun_AutoDetect_NoExtension_ReturnsError(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls":        minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	})
	if err == nil {
		t.Fatal("expected error when --from cannot be auto-detected, got nil")
	}
	if !strings.Contains(err.Error(), "--from") {
		t.Errorf("error should mention --from: %v", err)
	}
}

// ---- emit-format tests ------------------------------------------------------

func TestRun_EmitFormat_Script_ProducesShebang(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	if err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	}); err != nil {
		t.Fatalf("convert: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "#!/usr/bin/env bash") {
		t.Errorf("script output should start with shebang:\n%s", out)
	}
	if !strings.Contains(out, "confluent iam rbac role-binding create") {
		t.Errorf("script output should contain confluent CLI command:\n%s", out)
	}
}

func TestRun_EmitFormat_CFK_ProducesYAML(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	if err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "cfk",
	}); err != nil {
		t.Fatalf("convert: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "kind: ConfluentRolebinding") {
		t.Errorf("cfk output should contain CRD kind:\n%s", out)
	}
	if !strings.Contains(out, "apiVersion: platform.confluent.io/v1beta1") {
		t.Errorf("cfk output should contain apiVersion:\n%s", out)
	}
}

func TestRun_EmitFormat_MDSCurl_ProducesShebang(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	if err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "mds-curl",
	}); err != nil {
		t.Fatalf("convert: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "#!/usr/bin/env bash") {
		t.Errorf("mds-curl output should start with shebang:\n%s", out)
	}
	if !strings.Contains(out, "curl") {
		t.Errorf("mds-curl output should contain curl commands:\n%s", out)
	}
}

func TestRun_EmitFormat_Unknown_ReturnsError(t *testing.T) {
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
	})
	var buf bytes.Buffer
	err := convert.Run(&buf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "invalidfmt",
	})
	if err == nil {
		t.Fatal("expected error for unknown --format, got nil")
	}
	if !strings.Contains(err.Error(), "invalidfmt") {
		t.Errorf("error should mention the bad emit format: %v", err)
	}
}

// ---- custom --rules override ------------------------------------------------

func TestRun_CustomRules_OverrideRole(t *testing.T) {
	customRules := `rules:
  - when:
      operations: [Read, Describe]
      operations_mode: all
      resource_type: Topic
      permission_type: Allow
    then:
      role: CustomRole
      scope_template: kafka-cluster
`
	dir := writeFixtures(t, map[string]string{
		"acls.yaml":   minimalACLSetYAML,
		"scopes.yaml": scopesYAML,
		"rules.yaml":  customRules,
	})

	// Without custom rules: DeveloperRead.
	var defaultBuf bytes.Buffer
	if err := convert.Run(&defaultBuf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		EmitFormat: "script",
	}); err != nil {
		t.Fatalf("default rules: %v", err)
	}
	if !strings.Contains(defaultBuf.String(), "DeveloperRead") {
		t.Errorf("default rules should produce DeveloperRead:\n%s", defaultBuf.String())
	}

	// With custom rules: CustomRole instead.
	var customBuf bytes.Buffer
	if err := convert.Run(&customBuf, convert.Options{
		InputPath:  filepath.Join(dir, "acls.yaml"),
		ScopesPath: filepath.Join(dir, "scopes.yaml"),
		RulesPath:  filepath.Join(dir, "rules.yaml"),
		EmitFormat: "script",
	}); err != nil {
		t.Fatalf("custom rules: %v", err)
	}
	out := customBuf.String()
	if !strings.Contains(out, "CustomRole") {
		t.Errorf("custom rules should produce CustomRole:\n%s", out)
	}
	if strings.Contains(out, "DeveloperRead") {
		t.Errorf("custom rules should override DeveloperRead:\n%s", out)
	}
}
