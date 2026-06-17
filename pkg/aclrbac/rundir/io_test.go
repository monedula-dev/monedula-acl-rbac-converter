// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestWriteAndReadACLs_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acls.json")

	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs: []types.ACLRow{{
			ID: 1, Principal: "User:alice", Host: "*",
			Operation: types.OpRead, ResourceType: types.ResourceTopic,
			ResourceName: "orders", PatternType: types.PatternLiteral,
			PermissionType: types.PermissionAllow,
		}},
	}

	if err := rundir.WriteACLs(path, set); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := rundir.ReadACLs(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.ACLs) != 1 || got.ACLs[0].Principal != "User:alice" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestReadACLs_RejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acls.json")
	// Missing required fields.
	if err := rundir.WriteRawForTest(path, []byte(`{"schema_version": "1","source":{"type":"json","generated_at":"2026-05-21T10:00:00Z"},"acls":[{"id":1}]}`)); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := rundir.ReadACLs(path)
	if err == nil {
		t.Fatal("expected schema validation error")
	}
}

func TestWriteAndReadPlan_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")

	plan := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Bindings: []types.Binding{{
			ID:        "rb-abcdef012345",
			Action:    types.ActionCreate,
			Principal: "User:alice",
			Role:      "DeveloperRead",
			Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{
				ResourceType: types.ResourceTopic,
				Name:         "orders",
				PatternType:  types.PatternLiteral,
			}},
			SourceACLIDs: []int{1},
		}},
		Unmapped:     []types.UnmappedEntry{},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}

	if err := rundir.WritePlan(path, plan); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := rundir.ReadPlan(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Bindings) != 1 {
		t.Errorf("bindings: got %d", len(got.Bindings))
	}
}
