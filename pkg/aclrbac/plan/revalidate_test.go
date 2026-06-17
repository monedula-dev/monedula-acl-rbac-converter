// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestRevalidate_RemovedBindingTriggersNoError(t *testing.T) {
	// Start from a valid plan, then drop a binding (simulating operator
	// removing one before `apply`).
	original := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{{
			ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
			Principal: "User:alice", Role: "DeveloperRead",
			Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{
				ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
			}},
			SourceACLIDs: []int{1, 2},
		}},
		Unmapped:     []types.UnmappedEntry{},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}
	edited := original
	edited.Bindings = []types.Binding{} // operator removed everything

	out, err := plan.Revalidate(edited)
	if err != nil {
		t.Fatalf("revalidate: %v", err)
	}
	if len(out.Bindings) != 0 {
		t.Errorf("edited plan should still have 0 bindings; got %d", len(out.Bindings))
	}
}

func TestRevalidate_RejectsInvalidActionValue(t *testing.T) {
	p := types.Plan{
		SchemaVersion: "1", GeneratedAt: "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{{
			ID: "rb-aaaaaaaaaaaa", Action: types.Action("BOGUS_ACTION"),
			Principal: "User:alice", Role: "DeveloperRead",
			Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
		}},
	}

	_, err := plan.Revalidate(p)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}
