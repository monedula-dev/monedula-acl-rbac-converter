// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types_test

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestPatternsOverlap(t *testing.T) {
	const (
		lit = types.PatternLiteral
		pre = types.PatternPrefixed
	)
	cases := []struct {
		name  string
		aType types.PatternType
		aName string
		bType types.PatternType
		bName string
		want  bool
	}{
		// LITERAL ∩ LITERAL
		{"lit==lit overlap", lit, "orders", lit, "orders", true},
		{"lit!=lit disjoint", lit, "orders", lit, "payments", false},

		// The release-blocker cases: an Allow INSIDE a denied prefix.
		{"literal inside prefixed deny", lit, "secret-prod", pre, "secret-", true},
		{"narrower prefix inside prefixed deny", pre, "secret-prod-", pre, "secret-", true},
		{"prefixed deny inside broader allow prefix", pre, "secret-", pre, "sec", true},
		{"literal outside prefixed deny", lit, "public-data", pre, "secret-", false},

		// PREFIXED ∩ LITERAL both directions
		{"deny literal inside allow prefix", pre, "orders.", lit, "orders.processed", true},
		{"allow literal not under deny prefix", pre, "orders.", lit, "payments", false},

		// PREFIXED ∩ PREFIXED
		{"disjoint prefixes", pre, "orders.", pre, "payments.", false},
		{"equal prefixes", pre, "orders.", pre, "orders.", true},

		// Wildcard-all literal
		{"allow star covers any prefixed deny", lit, "*", pre, "secret-", true},
		{"deny star covers any literal allow", lit, "orders", lit, "*", true},
		{"star vs star", lit, "*", lit, "*", true},

		// Empty prefix matches everything.
		{"empty allow prefix covers all", pre, "", lit, "anything", true},

		// --- boundary / wrong-oracle cases ---

		// The literal "*" is Kafka's wildcard-all, but a PREFIXED "*" is NOT:
		// it's the namespace of names that literally START with an asterisk.
		// Conflating the two would make a DENY look removable (or unremovable)
		// against the wrong universe of resources.
		{"prefixed-asterisk is not wildcard-all (disjoint literal)", pre, "*", lit, "orders", false},
		{"prefixed-asterisk matches only names starting with asterisk", pre, "*", lit, "*danger", true},
		{"prefixed-asterisk vs literal-asterisk wildcard overlaps", pre, "*", lit, "*", true},
		{"two prefixed asterisks overlap (equal prefix)", pre, "*", pre, "*", true},

		// Resource names are case-sensitive in Kafka. "Secret-" and "secret-"
		// denote different namespaces; an accidental case-fold would wrongly
		// report overlap and mis-classify DENY removal safety.
		{"literal case-sensitive disjoint", lit, "Orders", lit, "orders", false},
		{"prefixed case-sensitive disjoint", lit, "Secret-prod", pre, "secret-", false},
		{"prefixed case-sensitive same-case overlaps", lit, "secret-prod", pre, "secret-", true},

		// Trailing dot is part of the name: the PREFIXED "orders." namespace
		// does NOT contain the LITERAL "orders" (no dot), but does contain
		// "orders." and anything under it.
		{"trailing-dot prefix excludes the dotless literal", pre, "orders.", lit, "orders", false},
		{"trailing-dot prefix includes the exact dotted literal", pre, "orders.", lit, "orders.", true},
		{"prefix without dot includes the dotless literal", pre, "orders", lit, "orders", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := types.PatternsOverlap(tc.aType, tc.aName, tc.bType, tc.bName); got != tc.want {
				t.Errorf("PatternsOverlap(%s %q, %s %q) = %v, want %v",
					tc.aType, tc.aName, tc.bType, tc.bName, got, tc.want)
			}
			// Symmetry: the predicate must be order-independent.
			if got := types.PatternsOverlap(tc.bType, tc.bName, tc.aType, tc.aName); got != tc.want {
				t.Errorf("asymmetric: PatternsOverlap(%s %q, %s %q) = %v, want %v",
					tc.bType, tc.bName, tc.aType, tc.aName, got, tc.want)
			}
		})
	}
}
