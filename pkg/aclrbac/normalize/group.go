// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package normalize implements the pre-planning normalization described in
// spec §3.0: group ACL rows by tuple, expand ALL, deduplicate while
// preserving source identity.
package normalize

import (
	"sort"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// ACLGroup is a set of ACL rows that share everything except the operation.
// The Operations map records which operations are present (as a set).
// SourceACLIDs preserves the original row IDs for cross-referencing into
// plan.json::bindings[].source_acl_ids[].
type ACLGroup struct {
	Principal      string
	Host           string
	ResourceType   types.ResourceType
	ResourceName   string
	PatternType    types.PatternType
	PermissionType types.PermissionType
	Operations     map[types.Operation]bool
	SourceACLIDs   []int
}

// HasOp is a convenience for matching code.
func (g ACLGroup) HasOp(op types.Operation) bool { return g.Operations[op] }

// GroupRows groups ACL rows by everything except operation. Within each group
// the operation set is the union of the rows' operations and SourceACLIDs is
// the union of their IDs (sorted ascending for stability).
func GroupRows(rows []types.ACLRow) []ACLGroup {
	type key struct {
		principal      string
		host           string
		resourceType   types.ResourceType
		resourceName   string
		patternType    types.PatternType
		permissionType types.PermissionType
	}
	idx := map[key]*ACLGroup{}

	for _, r := range rows {
		k := key{
			principal:      r.Principal,
			host:           r.Host,
			resourceType:   r.ResourceType,
			resourceName:   r.ResourceName,
			patternType:    r.PatternType,
			permissionType: r.PermissionType,
		}
		g, ok := idx[k]
		if !ok {
			g = &ACLGroup{
				Principal:      r.Principal,
				Host:           r.Host,
				ResourceType:   r.ResourceType,
				ResourceName:   r.ResourceName,
				PatternType:    r.PatternType,
				PermissionType: r.PermissionType,
				Operations:     map[types.Operation]bool{},
			}
			idx[k] = g
		}
		g.Operations[r.Operation] = true
		g.SourceACLIDs = append(g.SourceACLIDs, r.ID)
	}

	out := make([]ACLGroup, 0, len(idx))
	for _, g := range idx {
		sort.Ints(g.SourceACLIDs)
		out = append(out, *g)
	}
	// Deterministic order for tests, reports and plan.sha256: the comparator
	// MUST be a total order over the full group key, otherwise groups that tie
	// on a subset of fields are ordered by Go's randomized map iteration and
	// the plan becomes non-deterministic across runs. Compare every one of the
	// six key fields.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Principal != b.Principal {
			return a.Principal < b.Principal
		}
		if a.ResourceType != b.ResourceType {
			return a.ResourceType < b.ResourceType
		}
		if a.ResourceName != b.ResourceName {
			return a.ResourceName < b.ResourceName
		}
		if a.PatternType != b.PatternType {
			return a.PatternType < b.PatternType
		}
		if a.PermissionType != b.PermissionType {
			return a.PermissionType < b.PermissionType
		}
		return a.Host < b.Host
	})
	return out
}
