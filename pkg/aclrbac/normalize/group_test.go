// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package normalize_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/normalize"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestGroupRows_DeterministicOrderAcrossAllKeyFields pins that the output
// order is fully determined even when groups differ only in fields the old
// comparator ignored (Host, PatternType, PermissionType). The group key has
// six fields but the comparator sorted on only three, so groups differing in
// the other three tied and the unstable sort leaked Go's randomized map
// iteration order into the plan. Running GroupRows repeatedly must yield a
// byte-identical sequence.
func TestGroupRows_DeterministicOrderAcrossAllKeyFields(t *testing.T) {
	rows := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 2, Principal: "User:alice", Host: "10.0.0.1", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 3, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternPrefixed, PermissionType: types.PermissionAllow},
		{ID: 4, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
	}

	fingerprint := func(gs []normalize.ACLGroup) string {
		s := ""
		for _, g := range gs {
			s += string(g.PermissionType) + "|" + g.Host + "|" + string(g.PatternType) + "\n"
		}
		return s
	}

	want := fingerprint(normalize.GroupRows(rows))
	for i := 0; i < 200; i++ {
		if got := fingerprint(normalize.GroupRows(rows)); got != want {
			t.Fatalf("non-deterministic group order on run %d:\nfirst:\n%s\ngot:\n%s", i, want, got)
		}
	}
}

func TestGroupRows_GroupsByTuple(t *testing.T) {
	rows := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 3, Principal: "User:bob", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}

	groups := normalize.GroupRows(rows)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (alice + bob)", len(groups))
	}

	// Alice's group has both Read and Describe.
	for _, g := range groups {
		if g.Principal == "User:alice" {
			if !g.Operations[types.OpRead] || !g.Operations[types.OpDescribe] {
				t.Errorf("alice group missing Read or Describe: %v", g.Operations)
			}
			if len(g.SourceACLIDs) != 2 {
				t.Errorf("alice source IDs: got %d, want 2", len(g.SourceACLIDs))
			}
		}
	}
}

func TestGroupRows_DistinctByResourceName(t *testing.T) {
	rows := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "shipments", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}
	groups := normalize.GroupRows(rows)
	if len(groups) != 2 {
		t.Errorf("got %d groups, want 2 (orders + shipments)", len(groups))
	}
}

func TestGroupRows_AllowAndDenyAreSeparate(t *testing.T) {
	rows := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionDeny},
	}
	groups := normalize.GroupRows(rows)
	if len(groups) != 2 {
		t.Errorf("got %d groups, want 2 (allow + deny)", len(groups))
	}
}
