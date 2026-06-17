// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package plan applies mapping rules to normalized ACL groups and produces a
// RoleBindingPlan. It is pure: no I/O, no globals, deterministic.
package plan

import (
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/normalize"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// MatchesRule reports whether g satisfies r's `when` clause.
func MatchesRule(g normalize.ACLGroup, r config.Rule) bool {
	if g.ResourceType != r.When.ResourceType {
		return false
	}
	if g.PermissionType != r.When.PermissionType {
		return false
	}
	switch r.When.OperationsMode {
	case config.OperationsModeAll:
		for _, op := range r.When.Operations {
			if !g.Operations[op] {
				return false
			}
		}
		return true
	case config.OperationsModeAny:
		for _, op := range r.When.Operations {
			if g.Operations[op] {
				return true
			}
		}
		return false
	default:
		// Unknown mode treated as no match — parser should have rejected this
		// earlier (see config.validateRule).
		return false
	}
}

// ruleCoveredOps returns the group operations the rule's role accounts for. As
// in uncoveredOps, the rule's `when` operations (plus the operations Kafka
// implies from them) are used as the proxy for what the role grants — the
// default rules are authored so the two coincide. An `All` rule covers every
// operation the group holds.
func ruleCoveredOps(g normalize.ACLGroup, rule config.Rule) map[types.Operation]bool {
	covered := map[types.Operation]bool{}
	for _, op := range rule.When.Operations {
		if op == types.OpAll {
			for gop := range g.Operations {
				covered[gop] = true
			}
			return covered
		}
		covered[op] = true
		for _, imp := range normalize.ImpliedOps[op] {
			covered[imp] = true
		}
	}
	return covered
}

// FindCoveringRules greedily selects the rules needed to cover a group's
// operations, walking the rule list in priority order. It returns the selected
// rules (in priority order) and is the basis for emitting one binding per role.
//
// Rationale: a single role cannot express a principal that is both a consumer
// and a producer (Read+Write on a topic). Rather than matching only the first
// rule (which silently drops the other intent) or matching every rule (which
// would spawn DeveloperRead/DeveloperWrite for an `ALL` group that should be a
// single ResourceOwner), we cover greedily: take the highest-priority matching
// rule, mark the operations it covers, and keep going only while operations
// remain uncovered. An `ALL` group's first match (ResourceOwner/SystemAdmin)
// covers everything, so the loop stops immediately — preserving the precedence
// the rule ordering encodes. A Read+Write group needs both DeveloperRead and
// DeveloperWrite to be fully covered, so both are selected.
//
// A rule is only selected if it covers at least one still-uncovered operation,
// so a lower-priority rule that adds a role but no new coverage is skipped.
// Returns nil if no rule matches the group at all.
func FindCoveringRules(g normalize.ACLGroup, rules []config.Rule) []config.Rule {
	// Operations still needing coverage. The `All` marker is not a concrete
	// operation to cover — ExpandAll has already added the concrete ops it
	// implies — so exclude it.
	remaining := map[types.Operation]bool{}
	for op := range g.Operations {
		if op == types.OpAll {
			continue
		}
		remaining[op] = true
	}

	var selected []config.Rule
	for i := range rules {
		if len(remaining) == 0 {
			break
		}
		if !MatchesRule(g, rules[i]) {
			continue
		}
		covered := ruleCoveredOps(g, rules[i])
		coversNew := false
		for op := range covered {
			if remaining[op] {
				coversNew = true
				break
			}
		}
		if !coversNew {
			continue
		}
		selected = append(selected, rules[i])
		for op := range covered {
			delete(remaining, op)
		}
	}
	return selected
}
