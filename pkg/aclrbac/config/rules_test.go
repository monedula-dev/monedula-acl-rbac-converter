// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestParseRules_BasicRule(t *testing.T) {
	data := []byte(`
rules:
  - when:
      operations: [Read, Describe]
      operations_mode: all
      resource_type: Topic
      permission_type: Allow
    then:
      role: DeveloperRead
      scope_template: kafka-cluster
`)
	rules, err := config.ParseRules(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.When.OperationsMode != config.OperationsModeAll {
		t.Errorf("mode: got %q, want all", r.When.OperationsMode)
	}
	if r.When.ResourceType != types.ResourceTopic {
		t.Errorf("resource: got %q", r.When.ResourceType)
	}
	if r.Then.Role != "DeveloperRead" {
		t.Errorf("role: got %q", r.Then.Role)
	}
}

func TestParseRules_RejectsUnknownOperation(t *testing.T) {
	// Lowercase "read" is not a valid Kafka operation. Without enum validation
	// it parses cleanly and produces a rule that can never match, so the ACLs
	// silently land in unmapped/NO_RULE_MATCH — easily misread as missing
	// coverage rather than a config typo.
	data := []byte(`
rules:
  - when:
      operations: [read]
      operations_mode: all
      resource_type: Topic
      permission_type: Allow
    then:
      role: DeveloperRead
`)
	if _, err := config.ParseRules(data); err == nil {
		t.Error("expected error for unknown operation 'read'")
	}
}

func TestParseRules_RejectsUnknownResourceType(t *testing.T) {
	data := []byte(`
rules:
  - when:
      operations: [Read]
      operations_mode: all
      resource_type: topic
      permission_type: Allow
    then:
      role: DeveloperRead
`)
	if _, err := config.ParseRules(data); err == nil {
		t.Error("expected error for unknown resource_type 'topic'")
	}
}

func TestParseRules_DefaultMode(t *testing.T) {
	data := []byte(`
rules:
  - when:
      operations: [Read]
      resource_type: Topic
      permission_type: Allow
    then:
      role: DeveloperRead
      scope_template: kafka-cluster
`)
	rules, err := config.ParseRules(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rules[0].When.OperationsMode != config.OperationsModeAll {
		t.Errorf("default mode: got %q, want all", rules[0].When.OperationsMode)
	}
}

func TestLoadDefaultsParses(t *testing.T) {
	yamlData, err := config.DefaultRulesYAML()
	if err != nil {
		t.Fatalf("read defaults: %v", err)
	}
	rules, err := config.ParseRules(yamlData)
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	if len(rules) < 5 {
		t.Errorf("defaults should have multiple rules; got %d", len(rules))
	}
}

func TestMergeRules_OverrideByKey(t *testing.T) {
	defaults := []config.Rule{
		{
			When: config.RuleWhen{
				Operations:     []types.Operation{types.OpRead, types.OpDescribe},
				OperationsMode: config.OperationsModeAll,
				ResourceType:   types.ResourceTopic,
				PermissionType: types.PermissionAllow,
			},
			Then: config.RuleThen{Role: "DeveloperRead", ScopeTemplate: "kafka-cluster"},
		},
	}
	overrides := []config.Rule{
		{
			When: config.RuleWhen{
				Operations:     []types.Operation{types.OpRead, types.OpDescribe},
				OperationsMode: config.OperationsModeAll,
				ResourceType:   types.ResourceTopic,
				PermissionType: types.PermissionAllow,
			},
			Then: config.RuleThen{Role: "CustomReadRole", ScopeTemplate: "kafka-cluster"},
		},
	}
	merged := config.MergeRules(defaults, overrides)
	if len(merged) != 1 {
		t.Fatalf("merged: got %d, want 1", len(merged))
	}
	if merged[0].Then.Role != "CustomReadRole" {
		t.Errorf("override didn't win: got %q", merged[0].Then.Role)
	}
}

func TestMergeRules_AdditiveForNewKeys(t *testing.T) {
	defaults := []config.Rule{{
		When: config.RuleWhen{
			Operations:     []types.Operation{types.OpRead, types.OpDescribe},
			OperationsMode: config.OperationsModeAll,
			ResourceType:   types.ResourceTopic,
			PermissionType: types.PermissionAllow,
		},
		Then: config.RuleThen{Role: "DeveloperRead"},
	}}
	overrides := []config.Rule{{
		When: config.RuleWhen{
			Operations:     []types.Operation{types.OpDelete},
			OperationsMode: config.OperationsModeAny,
			ResourceType:   types.ResourceTopic,
			PermissionType: types.PermissionAllow,
		},
		Then: config.RuleThen{Role: "ResourceOwner"},
	}}
	merged := config.MergeRules(defaults, overrides)
	if len(merged) != 2 {
		t.Errorf("merged: got %d, want 2 (default + new override)", len(merged))
	}
}
