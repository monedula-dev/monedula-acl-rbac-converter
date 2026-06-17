// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package normalize_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/normalize"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestExpandAll_DoesNotMutateInput pins that ExpandAll treats its argument as
// immutable: it takes the group by value but used to write implied ops into
// g.Operations, which is a map and therefore shared with the caller's group.
// Any caller outside Normalize (which happens to pass fresh maps) would see
// its input mutated.
func TestExpandAll_DoesNotMutateInput(t *testing.T) {
	orig := normalize.ACLGroup{
		ResourceType: types.ResourceTopic,
		Operations:   map[types.Operation]bool{types.OpAll: true},
	}
	_ = normalize.ExpandAll(orig)
	if len(orig.Operations) != 1 || !orig.Operations[types.OpAll] {
		t.Errorf("ExpandAll mutated its input group's Operations map: %v", orig.Operations)
	}
}

func TestExpandAll_Topic(t *testing.T) {
	g := normalize.ACLGroup{
		Principal:      "User:alice",
		Host:           "*",
		ResourceType:   types.ResourceTopic,
		ResourceName:   "orders",
		PatternType:    types.PatternLiteral,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpAll: true},
		SourceACLIDs:   []int{1},
	}
	expanded := normalize.ExpandAll(g)

	// ALL on Topic should imply Read/Write/Create/Delete/Alter/Describe/DescribeConfigs/AlterConfigs.
	expectOps := []types.Operation{
		types.OpRead, types.OpWrite, types.OpCreate, types.OpDelete, types.OpAlter,
		types.OpDescribe, types.OpDescribeConfigs, types.OpAlterConfigs,
	}
	for _, op := range expectOps {
		if !expanded.Operations[op] {
			t.Errorf("expected %s in expanded ops", op)
		}
	}
	// The original ALL must remain so rule matching can still use it.
	if !expanded.Operations[types.OpAll] {
		t.Error("expected All to remain after expansion (preserved for rule matching)")
	}
	// SourceACLIDs unchanged — expansion never invents new IDs.
	if len(expanded.SourceACLIDs) != 1 || expanded.SourceACLIDs[0] != 1 {
		t.Errorf("source IDs changed: %v", expanded.SourceACLIDs)
	}
}

func TestExpandAll_NoOpForGroupWithoutAll(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType: types.ResourceTopic,
		Operations:   map[types.Operation]bool{types.OpRead: true},
		SourceACLIDs: []int{1},
	}
	expanded := normalize.ExpandAll(g)
	if expanded.Operations[types.OpWrite] {
		t.Error("expansion should not fire when ALL is absent")
	}
}

func TestExpandAllSet(t *testing.T) {
	groups := []normalize.ACLGroup{{
		ResourceType: types.ResourceCluster,
		Operations:   map[types.Operation]bool{types.OpAll: true},
		SourceACLIDs: []int{1},
	}}
	out := normalize.ExpandAllSet(groups)
	if len(out) != 1 {
		t.Fatalf("got %d groups, want 1", len(out))
	}
	if !out[0].Operations[types.OpClusterAction] {
		t.Errorf("ALL on Cluster should imply ClusterAction; got %v", out[0].Operations)
	}
}

// TestExpandImplied_AddsDescribeForWrite pins the core behavior: an Allow
// group holding only Write gains the implicitly-derived Describe (Kafka's
// authorizer treats Write/Read/Delete/Alter as implying Describe), so the
// group can match a [Write, Describe] rule.
func TestExpandImplied_AddsDescribeForWrite(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpWrite: true},
		SourceACLIDs:   []int{7},
	}
	expanded := normalize.ExpandImplied(g)
	if !expanded.Operations[types.OpDescribe] {
		t.Errorf("Write should imply Describe; got %v", expanded.Operations)
	}
	if !expanded.Operations[types.OpWrite] {
		t.Error("original Write op must be preserved")
	}
	// Expansion never invents source IDs — the implied Describe carries the
	// original Write row's ID through to the binding's source_acl_ids.
	if len(expanded.SourceACLIDs) != 1 || expanded.SourceACLIDs[0] != 7 {
		t.Errorf("source IDs changed: %v", expanded.SourceACLIDs)
	}
}

func TestExpandImplied_AlterConfigsImpliesDescribeConfigs(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpAlterConfigs: true},
	}
	expanded := normalize.ExpandImplied(g)
	if !expanded.Operations[types.OpDescribeConfigs] {
		t.Errorf("AlterConfigs should imply DescribeConfigs; got %v", expanded.Operations)
	}
}

// TestExpandImplied_SkipsDenyGroups is the safety-critical case: implicit
// derivation is an ALLOW-side semantic. Denying Write does NOT deny Describe,
// so a DENY group must never gain implied operations — doing so would
// fabricate denials the source ACLs never expressed.
func TestExpandImplied_SkipsDenyGroups(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionDeny,
		Operations:     map[types.Operation]bool{types.OpWrite: true},
	}
	expanded := normalize.ExpandImplied(g)
	if expanded.Operations[types.OpDescribe] {
		t.Errorf("DENY Write must NOT imply Describe; got %v", expanded.Operations)
	}
}

func TestExpandImplied_DoesNotMutateInput(t *testing.T) {
	orig := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpRead: true},
	}
	_ = normalize.ExpandImplied(orig)
	if len(orig.Operations) != 1 || !orig.Operations[types.OpRead] {
		t.Errorf("ExpandImplied mutated its input group's Operations map: %v", orig.Operations)
	}
}

func TestExpandImplied_LoneDescribeUnchanged(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpDescribe: true},
	}
	expanded := normalize.ExpandImplied(g)
	if len(expanded.Operations) != 1 || !expanded.Operations[types.OpDescribe] {
		t.Errorf("a lone Describe implies nothing; got %v", expanded.Operations)
	}
}

// TestNormalize_ExpandsImpliedDescribe pins that the full Normalize pipeline
// applies implied-op expansion: a lone Write row comes out as {Write, Describe}.
func TestNormalize_ExpandsImpliedDescribe(t *testing.T) {
	rows := []types.ACLRow{
		{ID: 1, Principal: "User:writer", Host: "*", Operation: types.OpWrite, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}
	groups := normalize.Normalize(rows)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if !groups[0].Operations[types.OpDescribe] {
		t.Errorf("Normalize should expand Write -> {Write, Describe}; got %v", groups[0].Operations)
	}
}

func TestNormalize_GroupsAndExpands(t *testing.T) {
	rows := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 3, Principal: "User:bob", Host: "*", Operation: types.OpAll, ResourceType: types.ResourceTopic, ResourceName: "shipments", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}

	groups := normalize.Normalize(rows)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}

	for _, g := range groups {
		if g.Principal == "User:bob" {
			if !g.Operations[types.OpRead] || !g.Operations[types.OpWrite] {
				t.Errorf("bob's ALL should imply Read+Write; got %v", g.Operations)
			}
		}
	}
}

func TestNormalize_DuplicateRowsCollapse(t *testing.T) {
	// Two identical rows from two source files (e.g., a text dump + a script).
	rows := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}

	groups := normalize.Normalize(rows)
	if len(groups) != 1 {
		t.Fatalf("duplicates should collapse; got %d groups", len(groups))
	}
	if len(groups[0].SourceACLIDs) != 2 {
		t.Errorf("both source IDs should be preserved; got %v", groups[0].SourceACLIDs)
	}
}
