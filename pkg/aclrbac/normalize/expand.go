// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package normalize

import "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"

// allImpliedOps lists the operations each resource type's `ALL` implies.
// Source: Apache Kafka's AclEntry / ResourceType matrix. The set is
// deliberately conservative — it includes every operation Kafka considers
// permitted by an `ALL` ACL for that resource type.
var allImpliedOps = map[types.ResourceType][]types.Operation{
	types.ResourceCluster: {
		types.OpCreate, types.OpDescribe, types.OpAlter, types.OpDescribeConfigs,
		types.OpAlterConfigs, types.OpClusterAction, types.OpIdempotentWrite,
	},
	types.ResourceTopic: {
		types.OpRead, types.OpWrite, types.OpCreate, types.OpDelete, types.OpAlter,
		types.OpDescribe, types.OpDescribeConfigs, types.OpAlterConfigs,
	},
	types.ResourceGroup: {
		types.OpRead, types.OpDelete, types.OpDescribe,
	},
	types.ResourceTransactionalID: {
		types.OpWrite, types.OpDescribe,
	},
	types.ResourceDelegationToken: {
		types.OpDescribe,
	},
	types.ResourceSubject: {
		types.OpRead, types.OpWrite, types.OpDescribe, types.OpDelete,
	},
}

// ExpandAll returns a copy of the group with the implied operations of `ALL`
// added to its operation set, preserving the `ALL` op itself for rule
// matching. The group's SourceACLIDs are not modified — implied operations
// carry the original ALL row's ID through the binding's source_acl_ids field.
//
// The input group is treated as immutable: g.Operations is a map and is shared
// with the caller, so we never write into it directly — we build a fresh map.
func ExpandAll(g ACLGroup) ACLGroup {
	if !g.Operations[types.OpAll] {
		return g
	}
	ops := make(map[types.Operation]bool, len(g.Operations)+len(allImpliedOps[g.ResourceType]))
	for op := range g.Operations {
		ops[op] = true
	}
	for _, op := range allImpliedOps[g.ResourceType] {
		ops[op] = true
	}
	g.Operations = ops
	return g
}

// ExpandAllSet applies ExpandAll to every group in the slice.
func ExpandAllSet(groups []ACLGroup) []ACLGroup {
	out := make([]ACLGroup, len(groups))
	for i, g := range groups {
		out[i] = ExpandAll(g)
	}
	return out
}

// ImpliedOps maps an operation to the operations Kafka's authorizer treats it
// as implicitly granting. Source: Apache Kafka AclEntry / AclAuthorizer — Read,
// Write, Delete and Alter all imply Describe; AlterConfigs implies
// DescribeConfigs. This is the canonical table; plan-side DENY analysis and
// coverage reporting reference it too, so it lives in the lowest package that
// needs it (normalize) to keep a single source of truth.
//
// IMPORTANT: these implications are an ALLOW-side semantic. Granting Write also
// grants Describe; denying Write does NOT deny Describe. ExpandImplied applies
// this only to Allow groups.
var ImpliedOps = map[types.Operation][]types.Operation{
	types.OpRead:         {types.OpDescribe},
	types.OpWrite:        {types.OpDescribe},
	types.OpDelete:       {types.OpDescribe},
	types.OpAlter:        {types.OpDescribe},
	types.OpAlterConfigs: {types.OpDescribeConfigs},
}

// ExpandImplied returns a copy of the group with each operation's
// implicitly-derived operations added (see ImpliedOps) — so a lone Allow Write
// becomes {Write, Describe} and can match a [Write, Describe] rule, mirroring
// what the broker's authorizer would actually permit. Like ExpandAll, it
// preserves SourceACLIDs unchanged: the implied op carries the original row's
// ID through to the binding's source_acl_ids.
//
// Non-Allow groups (DENY) are returned unchanged: denial is not transitive
// through implication. The input group is treated as immutable — a fresh
// Operations map is built rather than written into the shared one.
func ExpandImplied(g ACLGroup) ACLGroup {
	if g.PermissionType != types.PermissionAllow {
		return g
	}
	// Collect additions first so we don't decide based on a map we're mutating.
	var add []types.Operation
	for op := range g.Operations {
		add = append(add, ImpliedOps[op]...)
	}
	if len(add) == 0 {
		return g
	}
	ops := make(map[types.Operation]bool, len(g.Operations)+len(add))
	for op := range g.Operations {
		ops[op] = true
	}
	for _, op := range add {
		ops[op] = true
	}
	g.Operations = ops
	return g
}

// ExpandImpliedSet applies ExpandImplied to every group in the slice.
func ExpandImpliedSet(groups []ACLGroup) []ACLGroup {
	out := make([]ACLGroup, len(groups))
	for i, g := range groups {
		out[i] = ExpandImplied(g)
	}
	return out
}
