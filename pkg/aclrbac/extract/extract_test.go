// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package extract_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestWriteExtractedSet_WritesACLsAndSidecars(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "acls.json")

	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          []types.ACLRow{},
	}

	src := extract.ExtractSource{
		Kind:      "json",
		InputPath: "/tmp/some-input.json",
		Timestamp: time.Now(),
	}
	logger := extract.NewLogger()
	logger.Logf("PARSED line 1")
	logger.Logf("SKIPPED line 2: blank")

	if err := extract.WriteExtractedSet(out, set, nil, src, logger); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, name := range []string{"acls.json", "extract.log", "extract-source.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

func TestWriteExtractedSet_WritesExistingBindingsSidecar(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "acls.json")
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "cfk", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          []types.ACLRow{},
	}
	src := extract.ExtractSource{Kind: "cfk"}
	logger := extract.NewLogger()
	bindings := []types.Binding{
		{
			Action:    types.ActionCreate,
			Principal: "User:alice",
			Role:      "DeveloperRead",
			Scope:     types.Scope{KafkaCluster: "kafka"},
			ResourcePatterns: []types.ResourcePattern{
				{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral},
			},
		},
	}

	if err := extract.WriteExtractedSet(out, set, bindings, src, logger); err != nil {
		t.Fatalf("write: %v", err)
	}

	sidecar := filepath.Join(dir, "existing-bindings.json")
	data, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("expected existing-bindings.json next to acls.json; got %v", err)
	}
	if !strings.Contains(string(data), "User:alice") {
		t.Errorf("sidecar content: %s", data)
	}
}

func TestWriteExtractedSet_NoSidecarWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "acls.json")
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "text", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          []types.ACLRow{},
	}
	if err := extract.WriteExtractedSet(out, set, nil, extract.ExtractSource{Kind: "text"}, extract.NewLogger()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "existing-bindings.json")); !os.IsNotExist(err) {
		t.Errorf("sidecar should not exist for empty binding list; stat err = %v", err)
	}
}
