// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types

import "strings"

// IsWildcardPrincipal reports whether p is a Kafka wildcard principal: the
// bare "*" form (which some principal builders emit raw) or any typed
// "<Type>:*" form (e.g. "User:*", "Group:*").
//
// This is the single source of truth for "wildcard principal" across the
// codebase. The DENY-safety analysis and the delete-deny path MUST agree on
// it: a wildcard DENY covers principals the analysis cannot enumerate, so it
// can never be proven SAFE_TO_REMOVE. Two divergent predicates (one catching
// only ":*", another also catching bare "*") previously let a bare-"*" DENY be
// classified SAFE_TO_REMOVE by the planner while the delete path still treated
// it as a wildcard — an inconsistency that this shared helper removes.
//
// It does NOT match concrete principals that merely contain a literal star
// (e.g. "User:weird*name"): only the bare "*" and trailing ":*" forms are
// wildcard-shaped under Kafka's authorizer.
func IsWildcardPrincipal(p string) bool {
	return p == "*" || strings.HasSuffix(p, ":*")
}
