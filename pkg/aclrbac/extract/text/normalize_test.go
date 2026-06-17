// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package text

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Tests live in-package so they can exercise the unexported
// normalize* helpers directly. The text parser feeds these from
// kafka-acls.sh --list output (which uppercases everything); each
// must round-trip every spec-defined enum value into the canonical
// IR constant without losing information.

func TestNormalizeResourceType(t *testing.T) {
	cases := []struct {
		in   string
		want types.ResourceType
	}{
		{"TOPIC", types.ResourceTopic},
		{"topic", types.ResourceTopic}, // case-insensitive
		{"Topic", types.ResourceTopic},
		{"GROUP", types.ResourceGroup},
		{"CLUSTER", types.ResourceCluster},
		{"TRANSACTIONAL_ID", types.ResourceTransactionalID},
		{"TRANSACTIONALID", types.ResourceTransactionalID},
		{"DELEGATION_TOKEN", types.ResourceDelegationToken},
		{"DELEGATIONTOKEN", types.ResourceDelegationToken},
		{"SUBJECT", types.ResourceSubject},
		// Unknown values are preserved verbatim so the rejected-row
		// reporting path can still show what the input said.
		{"UNKNOWN_FUTURE_TYPE", types.ResourceType("UNKNOWN_FUTURE_TYPE")},
		{"", types.ResourceType("")},
	}
	for _, tc := range cases {
		got := normalizeResourceType(tc.in)
		if got != tc.want {
			t.Errorf("normalizeResourceType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeOperation(t *testing.T) {
	cases := []struct {
		in   string
		want types.Operation
	}{
		{"READ", types.OpRead},
		{"read", types.OpRead},
		{"Read", types.OpRead},
		{"WRITE", types.OpWrite},
		{"CREATE", types.OpCreate},
		{"DELETE", types.OpDelete},
		{"ALTER", types.OpAlter},
		{"DESCRIBE", types.OpDescribe},
		{"CLUSTER_ACTION", types.OpClusterAction},
		{"DESCRIBE_CONFIGS", types.OpDescribeConfigs},
		{"ALTER_CONFIGS", types.OpAlterConfigs},
		{"IDEMPOTENT_WRITE", types.OpIdempotentWrite},
		{"ALL", types.OpAll},
		// Unknown operations pass through verbatim (reporting path
		// surfaces the unrecognised value).
		{"UNKNOWN_FUTURE_OP", types.Operation("UNKNOWN_FUTURE_OP")},
		{"", types.Operation("")},
	}
	for _, tc := range cases {
		got := normalizeOperation(tc.in)
		if got != tc.want {
			t.Errorf("normalizeOperation(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
