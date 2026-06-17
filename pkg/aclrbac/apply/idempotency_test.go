// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package apply

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Tests live in-package (not _test) so they can exercise the unexported
// idempotency helpers alreadyHas + patternsEqual directly. These two
// functions decide whether apply marks a binding SkipExists or POSTs a
// new CreateRoleBinding; a bug in either would silently create
// duplicate bindings (false negative: thinks the binding is new when
// MDS already has it) or silently skip needed bindings (false
// positive: thinks the binding matches when it doesn't).

func topic(name string) types.ResourcePattern {
	return types.ResourcePattern{
		ResourceType: types.ResourceTopic,
		Name:         name,
		PatternType:  types.PatternLiteral,
	}
}

func group(name string) types.ResourcePattern {
	return types.ResourcePattern{
		ResourceType: types.ResourceGroup,
		Name:         name,
		PatternType:  types.PatternLiteral,
	}
}

func topicPrefix(name string) types.ResourcePattern {
	return types.ResourcePattern{
		ResourceType: types.ResourceTopic,
		Name:         name,
		PatternType:  types.PatternPrefixed,
	}
}

func TestPatternsEqual_EmptySlices(t *testing.T) {
	if !patternsEqual(nil, nil) {
		t.Error("two nil slices should be equal")
	}
	if !patternsEqual([]types.ResourcePattern{}, []types.ResourcePattern{}) {
		t.Error("two empty slices should be equal")
	}
	if !patternsEqual(nil, []types.ResourcePattern{}) {
		t.Error("nil and empty should be equal")
	}
}

func TestPatternsEqual_SamePatternsSameOrder(t *testing.T) {
	a := []types.ResourcePattern{topic("orders"), group("orders-consumer")}
	b := []types.ResourcePattern{topic("orders"), group("orders-consumer")}
	if !patternsEqual(a, b) {
		t.Error("identical pattern lists should compare equal")
	}
}

func TestPatternsEqual_SamePatternsDifferentOrder(t *testing.T) {
	// patternsEqual is a multiset comparison; order must not matter.
	a := []types.ResourcePattern{topic("orders"), group("orders-consumer")}
	b := []types.ResourcePattern{group("orders-consumer"), topic("orders")}
	if !patternsEqual(a, b) {
		t.Error("reordered patterns should compare equal (multiset semantics)")
	}
}

func TestPatternsEqual_DifferentLength(t *testing.T) {
	a := []types.ResourcePattern{topic("orders")}
	b := []types.ResourcePattern{topic("orders"), group("orders-consumer")}
	if patternsEqual(a, b) {
		t.Error("different-length slices must not compare equal")
	}
}

func TestPatternsEqual_PatternTypeDifference(t *testing.T) {
	// LITERAL vs PREFIXED on the same resource name are NOT equivalent;
	// scope must not be widened by an off-by-one comparison.
	a := []types.ResourcePattern{topic("billing")}
	b := []types.ResourcePattern{topicPrefix("billing")}
	if patternsEqual(a, b) {
		t.Errorf("LITERAL vs PREFIXED must not compare equal — scope widening risk")
	}
}

func TestPatternsEqual_DuplicatesRespectMultiplicity(t *testing.T) {
	// Multiset semantics: [orders, orders] != [orders, events].
	a := []types.ResourcePattern{topic("orders"), topic("orders")}
	b := []types.ResourcePattern{topic("orders"), topic("events")}
	if patternsEqual(a, b) {
		t.Error("duplicate patterns must count once each; mismatch should be detected")
	}
}

func TestAlreadyHas_ExactMatch(t *testing.T) {
	want := types.Binding{
		Principal:        "User:alice",
		Role:             "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{topic("orders")},
	}
	existing := []types.Binding{want}
	if !alreadyHas(existing, want) {
		t.Error("exact-equal binding should be detected as existing")
	}
}

func TestAlreadyHas_PrincipalMismatch(t *testing.T) {
	want := types.Binding{
		Principal:        "User:alice",
		Role:             "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{topic("orders")},
	}
	existing := []types.Binding{{
		Principal:        "User:bob",
		Role:             want.Role,
		Scope:            want.Scope,
		ResourcePatterns: want.ResourcePatterns,
	}}
	if alreadyHas(existing, want) {
		t.Error("different principal must not be reported as match")
	}
}

func TestAlreadyHas_RoleMismatch(t *testing.T) {
	want := types.Binding{
		Principal:        "User:alice",
		Role:             "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{topic("orders")},
	}
	existing := []types.Binding{{
		Principal:        want.Principal,
		Role:             "DeveloperWrite",
		Scope:            want.Scope,
		ResourcePatterns: want.ResourcePatterns,
	}}
	if alreadyHas(existing, want) {
		t.Error("different role must not be reported as match")
	}
}

func TestAlreadyHas_ScopeMismatch(t *testing.T) {
	want := types.Binding{
		Principal:        "User:alice",
		Role:             "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{topic("orders")},
	}
	existing := []types.Binding{{
		Principal:        want.Principal,
		Role:             want.Role,
		Scope:            types.Scope{KafkaCluster: "lkc-2"},
		ResourcePatterns: want.ResourcePatterns,
	}}
	if alreadyHas(existing, want) {
		t.Error("different scope must not be reported as match")
	}
}

func TestAlreadyHas_PatternMismatch(t *testing.T) {
	want := types.Binding{
		Principal:        "User:alice",
		Role:             "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{topic("orders")},
	}
	existing := []types.Binding{{
		Principal:        want.Principal,
		Role:             want.Role,
		Scope:            want.Scope,
		ResourcePatterns: []types.ResourcePattern{topic("events")},
	}}
	if alreadyHas(existing, want) {
		t.Error("different resource pattern must not be reported as match")
	}
}

func TestAlreadyHas_FindsAmongMultiple(t *testing.T) {
	target := types.Binding{
		Principal:        "User:alice",
		Role:             "DeveloperRead",
		Scope:            types.Scope{KafkaCluster: "lkc-1"},
		ResourcePatterns: []types.ResourcePattern{topic("orders")},
	}
	existing := []types.Binding{
		{Principal: "User:bob", Role: "DeveloperRead", Scope: target.Scope, ResourcePatterns: []types.ResourcePattern{topic("events")}},
		{Principal: "User:alice", Role: "DeveloperWrite", Scope: target.Scope, ResourcePatterns: []types.ResourcePattern{topic("orders")}},
		target,
		{Principal: "User:carol", Role: "DeveloperRead", Scope: target.Scope, ResourcePatterns: []types.ResourcePattern{topic("billing")}},
	}
	if !alreadyHas(existing, target) {
		t.Error("target binding present somewhere in list should be found")
	}
}

func TestAlreadyHas_EmptyExisting(t *testing.T) {
	want := types.Binding{Principal: "User:alice", Role: "DeveloperRead"}
	if alreadyHas(nil, want) {
		t.Error("nil existing list must report no match")
	}
	if alreadyHas([]types.Binding{}, want) {
		t.Error("empty existing list must report no match")
	}
}
