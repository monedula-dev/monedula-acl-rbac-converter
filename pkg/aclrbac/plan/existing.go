// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"sort"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// existingMatch represents a binding already in MDS / CFK manifests.
type existingMatch int

const (
	existingNoMatch                             existingMatch = iota
	existingEquivalent                                        // exact same (principal, role, scope, patterns) → SKIP_EXISTS
	existingSamePrincipalRoleDifferentResources               // → CONFLICTING_EXISTING_BINDING
)

// classifyAgainstExisting decides what the planner should do with `proposed`
// given the inventory of existing bindings.
func classifyAgainstExisting(proposed types.Binding, existing []types.Binding) (existingMatch, *types.Binding) {
	// Scan ALL candidates: a single principal commonly holds the same role on
	// several different resource sets, so the inventory may contain both an
	// exact equivalent and an unrelated same-(principal,role,scope) binding.
	// An exact equivalent means SKIP_EXISTS and must win regardless of where it
	// sits in the (MDS-controlled, unordered) list — returning on the first
	// non-equivalent match made the result depend on inventory order.
	var conflict *types.Binding
	for i, e := range existing {
		if e.Principal != proposed.Principal || e.Role != proposed.Role {
			continue
		}
		if !scopeEqual(e.Scope, proposed.Scope) {
			continue
		}
		if patternsEqual(e.ResourcePatterns, proposed.ResourcePatterns) {
			return existingEquivalent, &existing[i]
		}
		if conflict == nil {
			conflict = &existing[i]
		}
	}
	if conflict != nil {
		return existingSamePrincipalRoleDifferentResources, conflict
	}
	return existingNoMatch, nil
}

func scopeEqual(a, b types.Scope) bool { return a == b }

func patternsEqual(a, b []types.ResourcePattern) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]types.ResourcePattern{}, a...)
	sb := append([]types.ResourcePattern{}, b...)
	sortPatterns(sa)
	sortPatterns(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func sortPatterns(p []types.ResourcePattern) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].ResourceType != p[j].ResourceType {
			return p[i].ResourceType < p[j].ResourceType
		}
		if p[i].PatternType != p[j].PatternType {
			return p[i].PatternType < p[j].PatternType
		}
		return p[i].Name < p[j].Name
	})
}

// describeBinding returns a short string used in warning details / unmapped detail.
func describeBinding(b types.Binding) string {
	parts := make([]string, 0, len(b.ResourcePatterns))
	for _, p := range b.ResourcePatterns {
		parts = append(parts, string(p.ResourceType)+":"+p.Name+" ("+string(p.PatternType)+")")
	}
	joined := ""
	for i, s := range parts {
		if i > 0 {
			joined += ", "
		}
		joined += s
	}
	return b.Role + " on {" + joined + "} for " + b.Principal
}
