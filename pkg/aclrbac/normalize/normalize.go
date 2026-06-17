// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package normalize

import "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"

// Normalize is the planner's entry point. It groups raw ACL rows by tuple,
// expands `ALL` to its implied operations, expands each Allow group with the
// operations Kafka implicitly derives (e.g. Write implies Describe), and
// returns one ACLGroup per (principal, host, resource, pattern, permission)
// key. Duplicate rows collapse into the same group, with all duplicate source
// IDs preserved.
//
// ExpandAll runs before ExpandImplied so an `ALL` group is first widened to its
// concrete op set (which already includes Describe); ExpandImplied then only
// adds anything for groups built from explicit non-Describe ops.
func Normalize(rows []types.ACLRow) []ACLGroup {
	groups := GroupRows(rows)
	groups = ExpandAllSet(groups)
	return ExpandImpliedSet(groups)
}
