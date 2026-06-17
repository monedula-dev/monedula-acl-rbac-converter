// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types_test

import (
	"encoding/json"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestPlanRoundTrip(t *testing.T) {
	plan := types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{
			{
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
				SourceACLIDs: []int{1, 2},
			},
		},
		Unmapped:     []types.UnmappedEntry{},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}

	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.Plan
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Bindings[0].Action != types.ActionCreate {
		t.Errorf("action: got %q, want %q", got.Bindings[0].Action, types.ActionCreate)
	}
	if len(got.Bindings[0].SourceACLIDs) != 2 {
		t.Errorf("source IDs: got %d, want 2", len(got.Bindings[0].SourceACLIDs))
	}
}

func TestActionValues(t *testing.T) {
	if string(types.ActionCreate) != "CREATE" {
		t.Errorf("ActionCreate: got %q, want CREATE", types.ActionCreate)
	}
	if string(types.ActionSkipExists) != "SKIP_EXISTS" {
		t.Errorf("ActionSkipExists: got %q, want SKIP_EXISTS", types.ActionSkipExists)
	}
}
