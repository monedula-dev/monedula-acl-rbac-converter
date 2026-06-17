// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types

import "strings"

// PatternsOverlap reports whether two ACL resource patterns of the same
// resource type share at least one concrete resource name — i.e. their
// resource sets intersect. It is symmetric.
//
// This is the predicate DENY-safety analysis needs. Removing a DENY grants
// access iff some surviving Allow's resource set overlaps the DENY's set, so
// the question is intersection, NOT "does the Allow cover the DENY's literal
// name". The old check missed, for a DENY `secret-` PREFIXED, an Allow
// `secret-prod` LITERAL or `secret-prod-` PREFIXED that grants access to
// resources INSIDE the denied prefix — silently classifying the DENY
// SAFE_TO_REMOVE and granting access on removal.
//
// Pattern semantics (Kafka):
//   - LITERAL "name" is the single resource "name". The special LITERAL "*"
//     is Kafka's wildcard and matches every resource of the type.
//   - PREFIXED "p" is every resource whose name starts with "p" (the empty
//     prefix "" therefore matches everything).
func PatternsOverlap(aType PatternType, aName string, bType PatternType, bName string) bool {
	// Wildcard-all literal covers every resource of the type.
	if (aType == PatternLiteral && aName == "*") || (bType == PatternLiteral && bName == "*") {
		return true
	}
	switch {
	case aType == PatternLiteral && bType == PatternLiteral:
		// Two single resources intersect only if identical.
		return aName == bName
	case aType == PatternLiteral && bType == PatternPrefixed:
		// The literal is in b's namespace iff it starts with b's prefix.
		return strings.HasPrefix(aName, bName)
	case aType == PatternPrefixed && bType == PatternLiteral:
		return strings.HasPrefix(bName, aName)
	case aType == PatternPrefixed && bType == PatternPrefixed:
		// Two prefix namespaces intersect iff one prefix is a prefix of the
		// other (e.g. "secret-" and "secret-prod-" share "secret-prod-*").
		return strings.HasPrefix(aName, bName) || strings.HasPrefix(bName, aName)
	}
	// Unknown/future pattern type: be conservative — for DENY-safety the
	// caller treats "true" as "unsafe to remove", which is the safe default.
	return true
}
