// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestBindingID_DeterministicAndPrefixed(t *testing.T) {
	b := types.Binding{
		Principal: "User:alice",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{{
			ResourceType: types.ResourceTopic,
			Name:         "orders",
			PatternType:  types.PatternLiteral,
		}},
	}

	id1 := plan.BindingID(b, "")
	id2 := plan.BindingID(b, "")
	if id1 != id2 {
		t.Errorf("non-deterministic: %q vs %q", id1, id2)
	}
	if !strings.HasPrefix(id1, "rb-") {
		t.Errorf("missing prefix: %q", id1)
	}
	if len(id1) != 3+12 {
		t.Errorf("length: got %d, want 15", len(id1))
	}
}

func TestBindingID_OrderInsensitiveForResourcePatterns(t *testing.T) {
	b1 := types.Binding{
		Principal: "User:alice",
		Role:      "DeveloperRead",
		Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
		ResourcePatterns: []types.ResourcePattern{
			{ResourceType: types.ResourceTopic, Name: "a", PatternType: types.PatternLiteral},
			{ResourceType: types.ResourceTopic, Name: "b", PatternType: types.PatternLiteral},
		},
	}
	b2 := b1
	b2.ResourcePatterns = []types.ResourcePattern{
		{ResourceType: types.ResourceTopic, Name: "b", PatternType: types.PatternLiteral},
		{ResourceType: types.ResourceTopic, Name: "a", PatternType: types.PatternLiteral},
	}

	if plan.BindingID(b1, "") != plan.BindingID(b2, "") {
		t.Errorf("order of resource patterns should not change ID")
	}
}

func TestBindingID_SaltChangesHash(t *testing.T) {
	b := types.Binding{
		Principal: "User:alice", Role: "DeveloperRead",
		Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
	}
	if plan.BindingID(b, "") == plan.BindingID(b, "tenant-x") {
		t.Errorf("salt should change the hash")
	}
}
