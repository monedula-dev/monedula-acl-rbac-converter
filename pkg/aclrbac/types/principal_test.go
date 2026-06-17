// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestIsWildcardPrincipal pins the single source of truth the planner and the
// delete-deny path share. The bare "*" case is the regression guard: the
// planner once caught only ":*" while the delete path also caught "*", which
// let a bare-"*" DENY be (mis)classified SAFE_TO_REMOVE.
func TestIsWildcardPrincipal(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"*", true},       // bare wildcard — the inconsistency this closes
		{"User:*", true},  // typed wildcard
		{"Group:*", true}, // any type
		{"User:alice", false},
		{"User:weird*name", false}, // literal star mid-name is not wildcard-shaped
		{"User:*alice", false},     // only trailing ":*" counts
		{"", false},
		{"User:", false},
	}
	for _, tc := range cases {
		if got := types.IsWildcardPrincipal(tc.in); got != tc.want {
			t.Errorf("IsWildcardPrincipal(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
