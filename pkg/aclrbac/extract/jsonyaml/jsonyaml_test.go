// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package jsonyaml_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/jsonyaml"
)

func TestExtract_YAML(t *testing.T) {
	a, err := jsonyaml.New("testdata/basic.yaml")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, src, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 2 {
		t.Errorf("got %d ACLs, want 2", len(set.ACLs))
	}
	if src.InputSHA256 == "" {
		t.Errorf("InputSHA256 should be populated for file sources")
	}
}

func TestExtract_JSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "basic.json")

	// Re-encode the yaml fixture as JSON so we test both paths with one
	// fixture file checked in.
	yamlData, err := os.ReadFile("testdata/basic.yaml")
	if err != nil {
		t.Fatal(err)
	}
	jsonData := mustYAMLToJSONForTest(t, yamlData)
	if err := os.WriteFile(jsonPath, jsonData, 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := jsonyaml.New(jsonPath)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 2 {
		t.Errorf("got %d ACLs, want 2", len(set.ACLs))
	}
}

func TestExtract_InvalidSchemaRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": "1","source":{"type":"json","generated_at":"2026-05-21T10:00:00Z"},"acls":[{"id":1}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := jsonyaml.New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, _, _, _, err := a.Extract(); err == nil {
		t.Fatal("expected schema validation error")
	}
}

func mustYAMLToJSONForTest(t *testing.T, in []byte) []byte {
	t.Helper()
	var v interface{}
	if err := yaml.Unmarshal(in, &v); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	v = convertMapInterface(v)
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return data
}

func convertMapInterface(v interface{}) interface{} {
	switch x := v.(type) {
	case map[interface{}]interface{}:
		m := map[string]interface{}{}
		for k, val := range x {
			m[k.(string)] = convertMapInterface(val)
		}
		return m
	case map[string]interface{}:
		for k, val := range x {
			x[k] = convertMapInterface(val)
		}
		return x
	case []interface{}:
		for i := range x {
			x[i] = convertMapInterface(x[i])
		}
		return x
	}
	return v
}
