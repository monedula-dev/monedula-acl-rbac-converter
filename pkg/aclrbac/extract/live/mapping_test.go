// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package live

import (
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestMapOperation(t *testing.T) {
	cases := []struct {
		in   kmsg.ACLOperation
		want types.Operation
	}{
		{kmsg.ACLOperationRead, types.OpRead},
		{kmsg.ACLOperationWrite, types.OpWrite},
		{kmsg.ACLOperationCreate, types.OpCreate},
		{kmsg.ACLOperationDelete, types.OpDelete},
		{kmsg.ACLOperationAlter, types.OpAlter},
		{kmsg.ACLOperationDescribe, types.OpDescribe},
		{kmsg.ACLOperationClusterAction, types.OpClusterAction},
		{kmsg.ACLOperationDescribeConfigs, types.OpDescribeConfigs},
		{kmsg.ACLOperationAlterConfigs, types.OpAlterConfigs},
		{kmsg.ACLOperationIdempotentWrite, types.OpIdempotentWrite},
		{kmsg.ACLOperationAll, types.OpAll},
	}
	for _, c := range cases {
		got, ok := mapOperation(c.in)
		if !ok {
			t.Errorf("mapOperation(%v): not OK", c.in)
			continue
		}
		if got != c.want {
			t.Errorf("mapOperation(%v): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMapOperation_UnknownReturnsFalse(t *testing.T) {
	if _, ok := mapOperation(kmsg.ACLOperationAny); ok {
		t.Errorf("ACLOperationAny is a filter sentinel, must not map to a concrete op")
	}
	if _, ok := mapOperation(kmsg.ACLOperationUnknown); ok {
		t.Errorf("ACLOperationUnknown must not map")
	}
}

func TestMapResourceType(t *testing.T) {
	cases := []struct {
		in   kmsg.ACLResourceType
		want types.ResourceType
	}{
		{kmsg.ACLResourceTypeTopic, types.ResourceTopic},
		{kmsg.ACLResourceTypeGroup, types.ResourceGroup},
		{kmsg.ACLResourceTypeCluster, types.ResourceCluster},
		{kmsg.ACLResourceTypeTransactionalId, types.ResourceTransactionalID},
		{kmsg.ACLResourceTypeDelegationToken, types.ResourceDelegationToken},
	}
	for _, c := range cases {
		got, ok := mapResourceType(c.in)
		if !ok {
			t.Errorf("mapResourceType(%v): not OK", c.in)
			continue
		}
		if got != c.want {
			t.Errorf("mapResourceType(%v): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMapResourceType_UnknownReturnsFalse(t *testing.T) {
	if _, ok := mapResourceType(kmsg.ACLResourceTypeAny); ok {
		t.Errorf("Any is a filter sentinel, must not map")
	}
	if _, ok := mapResourceType(kmsg.ACLResourceTypeUser); ok {
		t.Errorf("User resource type has no canonical IR equivalent (Confluent only) - skip with ok=false")
	}
}

func TestMapPattern(t *testing.T) {
	cases := []struct {
		in   kmsg.ACLResourcePatternType
		want types.PatternType
	}{
		{kmsg.ACLResourcePatternTypeLiteral, types.PatternLiteral},
		{kmsg.ACLResourcePatternTypePrefixed, types.PatternPrefixed},
	}
	for _, c := range cases {
		got, ok := mapPattern(c.in)
		if !ok {
			t.Errorf("mapPattern(%v): not OK", c.in)
			continue
		}
		if got != c.want {
			t.Errorf("mapPattern(%v): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMapPattern_FilterSentinelsReturnFalse(t *testing.T) {
	// ANY and MATCH are filter-only patterns; described ACLs always come back
	// as LITERAL or PREFIXED. If we ever see one, treat as a mapping failure
	// so the caller can log + skip instead of silently inventing a type.
	if _, ok := mapPattern(kmsg.ACLResourcePatternTypeAny); ok {
		t.Errorf("ANY must not map")
	}
	if _, ok := mapPattern(kmsg.ACLResourcePatternTypeMatch); ok {
		t.Errorf("MATCH must not map")
	}
}

func TestMapPermission(t *testing.T) {
	cases := []struct {
		in   kmsg.ACLPermissionType
		want types.PermissionType
	}{
		{kmsg.ACLPermissionTypeAllow, types.PermissionAllow},
		{kmsg.ACLPermissionTypeDeny, types.PermissionDeny},
	}
	for _, c := range cases {
		got, ok := mapPermission(c.in)
		if !ok {
			t.Errorf("mapPermission(%v): not OK", c.in)
			continue
		}
		if got != c.want {
			t.Errorf("mapPermission(%v): got %q, want %q", c.in, got, c.want)
		}
	}
}
