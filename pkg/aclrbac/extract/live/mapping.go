// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// mapOperation translates a kmsg.ACLOperation to the canonical IR operation.
// Returns ok=false for filter sentinels (Any, Unknown) and for operations we
// don't have a canonical name for. CreateTokens / DescribeTokens are mapped
// to false here because the canonical IR doesn't yet include them (no
// Confluent RBAC role covers them either).
func mapOperation(op kmsg.ACLOperation) (types.Operation, bool) {
	switch op {
	case kmsg.ACLOperationRead:
		return types.OpRead, true
	case kmsg.ACLOperationWrite:
		return types.OpWrite, true
	case kmsg.ACLOperationCreate:
		return types.OpCreate, true
	case kmsg.ACLOperationDelete:
		return types.OpDelete, true
	case kmsg.ACLOperationAlter:
		return types.OpAlter, true
	case kmsg.ACLOperationDescribe:
		return types.OpDescribe, true
	case kmsg.ACLOperationClusterAction:
		return types.OpClusterAction, true
	case kmsg.ACLOperationDescribeConfigs:
		return types.OpDescribeConfigs, true
	case kmsg.ACLOperationAlterConfigs:
		return types.OpAlterConfigs, true
	case kmsg.ACLOperationIdempotentWrite:
		return types.OpIdempotentWrite, true
	case kmsg.ACLOperationAll:
		return types.OpAll, true
	}
	return "", false
}

// mapResourceType translates a kmsg.ACLResourceType to the canonical IR.
// Returns ok=false for Any/Unknown/User (User exists in Kafka 3.6+ for
// delegation-token quotas; the canonical IR has no equivalent).
func mapResourceType(rt kmsg.ACLResourceType) (types.ResourceType, bool) {
	switch rt {
	case kmsg.ACLResourceTypeTopic:
		return types.ResourceTopic, true
	case kmsg.ACLResourceTypeGroup:
		return types.ResourceGroup, true
	case kmsg.ACLResourceTypeCluster:
		return types.ResourceCluster, true
	case kmsg.ACLResourceTypeTransactionalId:
		return types.ResourceTransactionalID, true
	case kmsg.ACLResourceTypeDelegationToken:
		return types.ResourceDelegationToken, true
	}
	return "", false
}

// mapPattern translates a kmsg.ACLResourcePatternType to the canonical IR.
// Returns ok=false for ANY and MATCH, which are filter-only sentinels that
// should never appear on a described ACL.
func mapPattern(p kmsg.ACLResourcePatternType) (types.PatternType, bool) {
	switch p {
	case kmsg.ACLResourcePatternTypeLiteral:
		return types.PatternLiteral, true
	case kmsg.ACLResourcePatternTypePrefixed:
		return types.PatternPrefixed, true
	}
	return "", false
}

// mapPermission translates a kmsg.ACLPermissionType. ANY/Unknown -> ok=false.
func mapPermission(p kmsg.ACLPermissionType) (types.PermissionType, bool) {
	switch p {
	case kmsg.ACLPermissionTypeAllow:
		return types.PermissionAllow, true
	case kmsg.ACLPermissionTypeDeny:
		return types.PermissionDeny, true
	}
	return "", false
}
