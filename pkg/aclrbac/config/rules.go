// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// OperationsMode determines how the operations list in a rule's `when` clause
// is matched against an ACL group's operation set.
type OperationsMode string

const (
	// OperationsModeAll requires every listed operation to be present in the
	// group's operation set. This is the default.
	OperationsModeAll OperationsMode = "all"
	// OperationsModeAny matches if any one of the listed operations is in the
	// group's operation set. Used for rules like "All on Topic -> X".
	OperationsModeAny OperationsMode = "any"
)

// RuleWhen is a rule's matcher.
type RuleWhen struct {
	Operations     []types.Operation    `yaml:"operations"      json:"operations"`
	OperationsMode OperationsMode       `yaml:"operations_mode" json:"operations_mode"`
	ResourceType   types.ResourceType   `yaml:"resource_type"   json:"resource_type"`
	PermissionType types.PermissionType `yaml:"permission_type" json:"permission_type"`
}

// RuleThen is what to produce when a rule matches.
type RuleThen struct {
	Role          string `yaml:"role"           json:"role"`
	ScopeTemplate string `yaml:"scope_template" json:"scope_template"`
}

// Rule is one entry in defaults.yaml or a user rules.yaml.
type Rule struct {
	When RuleWhen `yaml:"when" json:"when"`
	Then RuleThen `yaml:"then" json:"then"`
}

// ParseRules parses a rules.yaml document. Empty input is valid and yields
// no rules.
func ParseRules(data []byte) ([]Rule, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var raw struct {
		Rules []Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse rules.yaml: %w", err)
	}
	for i := range raw.Rules {
		if raw.Rules[i].When.OperationsMode == "" {
			raw.Rules[i].When.OperationsMode = OperationsModeAll
		}
		if err := validateRule(raw.Rules[i], i); err != nil {
			return nil, err
		}
	}
	return raw.Rules, nil
}

// validOperations and validResourceTypes are the enums a rule's `when` clause
// may use. Without these checks a case typo (e.g. `read`, `topic`) parses
// cleanly but can never match, so the affected ACLs silently land in
// unmapped/NO_RULE_MATCH — easily misread as missing coverage.
var validOperations = map[types.Operation]bool{
	types.OpRead: true, types.OpWrite: true, types.OpCreate: true,
	types.OpDelete: true, types.OpAlter: true, types.OpDescribe: true,
	types.OpClusterAction: true, types.OpDescribeConfigs: true,
	types.OpAlterConfigs: true, types.OpIdempotentWrite: true, types.OpAll: true,
}

var validResourceTypes = map[types.ResourceType]bool{
	types.ResourceCluster: true, types.ResourceTopic: true, types.ResourceGroup: true,
	types.ResourceTransactionalID: true, types.ResourceDelegationToken: true,
	types.ResourceSubject: true,
}

func validateRule(r Rule, i int) error {
	if len(r.When.Operations) == 0 {
		return fmt.Errorf("rule %d: when.operations is empty", i)
	}
	for _, op := range r.When.Operations {
		if !validOperations[op] {
			return fmt.Errorf("rule %d: unknown operation %q in when.operations", i, op)
		}
	}
	switch r.When.OperationsMode {
	case OperationsModeAll, OperationsModeAny:
	default:
		return fmt.Errorf("rule %d: unknown operations_mode %q (allowed: all, any)", i, r.When.OperationsMode)
	}
	if r.When.ResourceType == "" {
		return fmt.Errorf("rule %d: when.resource_type missing", i)
	}
	if !validResourceTypes[r.When.ResourceType] {
		return fmt.Errorf("rule %d: unknown resource_type %q", i, r.When.ResourceType)
	}
	switch r.When.PermissionType {
	case types.PermissionAllow, types.PermissionDeny:
	default:
		return fmt.Errorf("rule %d: unknown permission_type %q", i, r.When.PermissionType)
	}
	if r.Then.Role == "" {
		return fmt.Errorf("rule %d: then.role missing", i)
	}
	return nil
}

// MergeRules merges overrides onto defaults, keyed by the rule's `when` shape.
// Overrides replace defaults; new override entries are appended.
//
// The key is canonical: operations are sorted, mode/resource/permission are
// included verbatim, so two rules that match the same shape collide.
func MergeRules(defaults, overrides []Rule) []Rule {
	out := make([]Rule, 0, len(defaults)+len(overrides))
	indexByKey := map[string]int{}

	for _, r := range defaults {
		k := whenKey(r.When)
		indexByKey[k] = len(out)
		out = append(out, r)
	}
	for _, r := range overrides {
		k := whenKey(r.When)
		if i, ok := indexByKey[k]; ok {
			out[i] = r
		} else {
			indexByKey[k] = len(out)
			out = append(out, r)
		}
	}
	return out
}

func whenKey(w RuleWhen) string {
	ops := make([]string, 0, len(w.Operations))
	for _, op := range w.Operations {
		ops = append(ops, string(op))
	}
	sort.Strings(ops)
	return strings.Join(ops, ",") + "|" + string(w.OperationsMode) + "|" + string(w.ResourceType) + "|" + string(w.PermissionType)
}
