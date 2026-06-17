// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"fmt"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/normalize"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// analyzeDenies classifies each DENY group against the set of Allow groups
// that survived planning (and the bindings the planner produced from them).
//
// A DENY for `(principal, op, resource)` is:
//   - WOULD_GRANT_ACCESS if any Allow rule grants the same principal + op
//     on a resource pattern that covers the DENY's resource (literal or
//     prefix match).
//   - UNKNOWN if the DENY's principal is a wildcard (User:*) or otherwise
//     cannot be matched against MDS group membership purely from input.
//   - SAFE_TO_REMOVE otherwise.
//
// The result is per source ACL row (one DENY ACLRow can have many ops).
func analyzeDenies(groups []normalize.ACLGroup, allACLs []types.ACLRow) []types.DenyAnalysisEntry {
	allowIdx := buildAllowIndex(groups)

	out := []types.DenyAnalysisEntry{}
	for _, r := range allACLs {
		if r.PermissionType != types.PermissionDeny {
			continue
		}
		status, covering := classifyDeny(r, allowIdx)
		out = append(out, types.DenyAnalysisEntry{
			SourceACLID:  r.ID,
			Status:       status,
			CoveringRule: covering,
		})
	}
	return out
}

// allowEntry is one Allow group flattened into the index. We store the
// resource pattern + op so lookup is O(allows) per DENY.
type allowEntry struct {
	principal    string
	op           types.Operation
	resourceType types.ResourceType
	resourceName string
	patternType  types.PatternType
}

type allowIndex struct {
	entries []allowEntry
}

func buildAllowIndex(groups []normalize.ACLGroup) allowIndex {
	idx := allowIndex{}
	for _, g := range groups {
		if g.PermissionType != types.PermissionAllow {
			continue
		}
		for op := range g.Operations {
			if op == types.OpAll {
				continue // implied ops already added by Normalize
			}
			idx.entries = append(idx.entries, allowEntry{
				principal:    g.Principal,
				op:           op,
				resourceType: g.ResourceType,
				resourceName: g.ResourceName,
				patternType:  g.PatternType,
			})
		}
	}
	return idx
}

// allowPrincipalCovers reports whether an Allow for allowPrincipal grants the
// DENY's (concrete, non-wildcard) principal. A wildcard Allow covers a concrete
// DENY: the bare "*" covers every principal, and "<Type>:*" covers every
// principal of that type. Removing a concrete DENY while such an Allow survives
// would grant access, so the DENY must not be classified SAFE_TO_REMOVE.
// denyPrincipal is guaranteed non-wildcard here (classifyDeny short-circuits
// wildcard DENYs to UNKNOWN before the overlap scan).
func allowPrincipalCovers(allowPrincipal, denyPrincipal string) bool {
	if allowPrincipal == denyPrincipal {
		return true
	}
	if allowPrincipal == "*" {
		return true
	}
	if t, ok := strings.CutSuffix(allowPrincipal, ":*"); ok {
		return strings.HasPrefix(denyPrincipal, t+":")
	}
	return false
}

// opImplies reports whether an Allow for allowOp implies the denyOp, per
// Kafka's implicit-operation rules (normalize.ImpliedOps is the canonical map).
func opImplies(allowOp, denyOp types.Operation) bool {
	for _, implied := range normalize.ImpliedOps[allowOp] {
		if implied == denyOp {
			return true
		}
	}
	return false
}

func classifyDeny(r types.ACLRow, idx allowIndex) (types.DenyAnalysisStatus, string) {
	// Wildcard principals — the bare "*" form and any typed "<Type>:*" form —
	// cannot be safely analyzed without resolving every possible principal that
	// could match. Treat as UNKNOWN so they are never auto-classified
	// SAFE_TO_REMOVE. Uses the shared types.IsWildcardPrincipal so the planner
	// and the delete-deny path agree on what "wildcard" means (a bare "*" once
	// slipped through here and was classified SAFE_TO_REMOVE).
	if types.IsWildcardPrincipal(r.Principal) {
		return types.DenyUnknown, ""
	}

	for _, a := range idx.entries {
		if !allowPrincipalCovers(a.principal, r.Principal) {
			continue
		}
		// Does the surviving Allow op cover the DENY op? A DENY whose operation
		// is `All` is never expanded by Normalize (only Allow groups are), so
		// r.Operation stays `All` — removing it exposes every surviving Allow
		// on the overlapping resource, so any allow op covers it. Otherwise the
		// allow op must equal the DENY op, be the catch-all `All` (which
		// buildAllowIndex never emits but we keep for safety), or *imply* the
		// DENY op under Kafka's authorizer rules (e.g. Allow Read implies
		// Describe), since removing the DENY would then expose that implied op.
		if r.Operation != types.OpAll && a.op != r.Operation && a.op != types.OpAll && !opImplies(a.op, r.Operation) {
			continue
		}
		if a.resourceType != r.ResourceType {
			continue
		}
		// Removing the DENY grants access iff the Allow's resource set
		// intersects the DENY's set. This MUST be a symmetric overlap, not
		// "does the Allow cover the DENY's literal name": for a DENY
		// `secret-` PREFIXED, an Allow `secret-prod` LITERAL (or a narrower
		// `secret-prod-` PREFIXED) grants access to resources INSIDE the
		// denied prefix and must mark the DENY WOULD_GRANT_ACCESS.
		if types.PatternsOverlap(a.patternType, a.resourceName, r.PatternType, r.ResourceName) {
			covering := fmt.Sprintf("Allow %s on %s:%s (%s) for %s",
				a.op, a.resourceType, a.resourceName, a.patternType, a.principal)
			return types.DenyWouldGrantAccess, covering
		}
	}
	return types.DenySafeToRemove, ""
}
