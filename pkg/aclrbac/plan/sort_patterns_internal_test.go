// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"reflect"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestSortPatterns_Deterministic pins the canonical ordering sortPatterns
// imposes before patternsEqual does its multiset comparison: primary key
// ResourceType, then PatternType, then Name. The ordering itself doesn't
// matter to a human, but it MUST be total and stable — patternsEqual relies
// on "sort both sides, compare element-wise", so two patterns differing in
// any one key must always land in the same relative order regardless of
// input order. A non-total comparator would make SKIP_EXISTS detection
// flaky (sometimes re-applying an already-present binding).
func TestSortPatterns_Deterministic(t *testing.T) {
	want := []types.ResourcePattern{
		{ResourceType: types.ResourceGroup, Name: "g1", PatternType: types.PatternLiteral},
		{ResourceType: types.ResourceTopic, Name: "a", PatternType: types.PatternLiteral},
		{ResourceType: types.ResourceTopic, Name: "b", PatternType: types.PatternLiteral},
		// PatternType beats Name: PREFIXED sorts after LITERAL regardless of
		// the name ("aaa" < "b" alphabetically, but LITERAL < PREFIXED wins).
		{ResourceType: types.ResourceTopic, Name: "aaa", PatternType: types.PatternPrefixed},
	}

	// Several scrambles of `want`; each must sort back to exactly `want`.
	scrambles := [][]types.ResourcePattern{
		{want[3], want[2], want[1], want[0]},
		{want[1], want[3], want[0], want[2]},
		{want[2], want[0], want[3], want[1]},
	}
	for i, in := range scrambles {
		got := append([]types.ResourcePattern(nil), in...)
		sortPatterns(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("scramble %d: sortPatterns produced %v, want %v", i, got, want)
		}
	}
}

// TestPatternsEqual_OrderIndependent is the contract sortPatterns exists to
// serve: two pattern sets that differ only in order are equal, and a genuine
// difference is not. This is what lets the planner mark an existing binding
// SKIP_EXISTS even when MDS returns its patterns in a different order than
// the planner generates them.
func TestPatternsEqual_OrderIndependent(t *testing.T) {
	a := []types.ResourcePattern{
		{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral},
		{ResourceType: types.ResourceGroup, Name: "cg", PatternType: types.PatternPrefixed},
	}
	b := []types.ResourcePattern{
		{ResourceType: types.ResourceGroup, Name: "cg", PatternType: types.PatternPrefixed},
		{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral},
	}
	if !patternsEqual(a, b) {
		t.Error("reordered identical pattern sets must be equal")
	}
	// patternsEqual must not mutate its inputs (it sorts copies). If it did,
	// the planner's binding would come out with reordered patterns.
	if a[0].Name != "orders" || b[0].PatternType != types.PatternPrefixed {
		t.Error("patternsEqual must not mutate its arguments")
	}

	// A real difference (different name) is not equal.
	c := []types.ResourcePattern{
		{ResourceType: types.ResourceTopic, Name: "payments", PatternType: types.PatternLiteral},
		{ResourceType: types.ResourceGroup, Name: "cg", PatternType: types.PatternPrefixed},
	}
	if patternsEqual(a, c) {
		t.Error("pattern sets differing in a name must not be equal")
	}

	// Different lengths are not equal.
	if patternsEqual(a, a[:1]) {
		t.Error("pattern sets of different length must not be equal")
	}
}
