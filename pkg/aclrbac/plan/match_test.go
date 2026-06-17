// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/normalize"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestMatch_AllRequiredOps(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpRead: true, types.OpDescribe: true},
	}
	r := config.Rule{
		When: config.RuleWhen{
			Operations:     []types.Operation{types.OpRead, types.OpDescribe},
			OperationsMode: config.OperationsModeAll,
			ResourceType:   types.ResourceTopic,
			PermissionType: types.PermissionAllow,
		},
		Then: config.RuleThen{Role: "DeveloperRead"},
	}
	if !plan.MatchesRule(g, r) {
		t.Error("group with all required ops should match")
	}
}

func TestMatch_MissingOneRequiredOpFails(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpRead: true},
	}
	r := config.Rule{
		When: config.RuleWhen{
			Operations:     []types.Operation{types.OpRead, types.OpDescribe},
			OperationsMode: config.OperationsModeAll,
			ResourceType:   types.ResourceTopic,
			PermissionType: types.PermissionAllow,
		},
		Then: config.RuleThen{Role: "DeveloperRead"},
	}
	if plan.MatchesRule(g, r) {
		t.Error("group missing Describe should NOT match all-mode rule")
	}
}

func TestMatch_AnyMode(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpDescribeConfigs: true},
	}
	r := config.Rule{
		When: config.RuleWhen{
			Operations:     []types.Operation{types.OpDescribeConfigs, types.OpAlterConfigs},
			OperationsMode: config.OperationsModeAny,
			ResourceType:   types.ResourceTopic,
			PermissionType: types.PermissionAllow,
		},
		Then: config.RuleThen{Role: "ResourceOwner"},
	}
	if !plan.MatchesRule(g, r) {
		t.Error("any-mode rule should match if at least one op is present")
	}
}

// rolesOf extracts the Then.Role of each selected rule, in order.
func rolesOf(rules []config.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Then.Role
	}
	return out
}

func TestFindCoveringRules_ReadWriteSelectsBoth(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpRead: true, types.OpWrite: true, types.OpDescribe: true},
	}
	got := rolesOf(plan.FindCoveringRules(g, basicRules(t)))
	if len(got) != 2 {
		t.Fatalf("Read+Write group should select 2 rules; got %v", got)
	}
	has := map[string]bool{got[0]: true, got[1]: true}
	if !has["DeveloperRead"] || !has["DeveloperWrite"] {
		t.Errorf("expected DeveloperRead and DeveloperWrite; got %v", got)
	}
}

// TestFindCoveringRules_AllStopsAtFirst pins the precedence invariant: an ALL
// group is covered entirely by the first matching rule (ResourceOwner), so
// greedy cover stops there rather than also picking the narrow Developer rules.
func TestFindCoveringRules_AllStopsAtFirst(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		// Mirror what Normalize produces for an ALL ACL: the marker plus the
		// concrete ops it implies.
		Operations: map[types.Operation]bool{
			types.OpAll: true, types.OpRead: true, types.OpWrite: true,
			types.OpCreate: true, types.OpDelete: true, types.OpAlter: true,
			types.OpDescribe: true, types.OpDescribeConfigs: true, types.OpAlterConfigs: true,
		},
	}
	got := rolesOf(plan.FindCoveringRules(g, basicRules(t)))
	if len(got) != 1 || got[0] != "ResourceOwner" {
		t.Fatalf("ALL on Topic should select only ResourceOwner; got %v", got)
	}
}

func TestFindCoveringRules_NoMatchReturnsNil(t *testing.T) {
	// A lone Delete on a Topic matches no default rule.
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionAllow,
		Operations:     map[types.Operation]bool{types.OpDelete: true, types.OpDescribe: true},
	}
	if got := plan.FindCoveringRules(g, basicRules(t)); got != nil {
		t.Errorf("lone Delete should match no rule; got %v", rolesOf(got))
	}
}

func TestMatch_ResourceTypeMustMatch(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType: types.ResourceGroup,
		Operations:   map[types.Operation]bool{types.OpRead: true},
	}
	r := config.Rule{
		When: config.RuleWhen{
			Operations:     []types.Operation{types.OpRead},
			OperationsMode: config.OperationsModeAll,
			ResourceType:   types.ResourceTopic,
		},
	}
	if plan.MatchesRule(g, r) {
		t.Error("resource type mismatch should not match")
	}
}

func TestMatch_PermissionMustMatch(t *testing.T) {
	g := normalize.ACLGroup{
		ResourceType:   types.ResourceTopic,
		PermissionType: types.PermissionDeny,
		Operations:     map[types.Operation]bool{types.OpRead: true},
	}
	r := config.Rule{
		When: config.RuleWhen{
			Operations:     []types.Operation{types.OpRead},
			OperationsMode: config.OperationsModeAll,
			ResourceType:   types.ResourceTopic,
			PermissionType: types.PermissionAllow,
		},
	}
	if plan.MatchesRule(g, r) {
		t.Error("permission mismatch should not match")
	}
}
