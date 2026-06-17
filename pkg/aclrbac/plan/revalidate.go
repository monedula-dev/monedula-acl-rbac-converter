// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"fmt"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Revalidate is the CLI's `plan --revalidate` entry. It accepts a hand-edited
// Plan, validates structural correctness (every Binding's Action is a known
// value; resource patterns reference known types; etc.), and returns the same
// Plan back with no mutation. The caller is expected to rewrite plan.sha256
// after this succeeds — Revalidate does not touch the filesystem.
//
// TRUST BOUNDARY: --revalidate re-checks only STRUCTURAL validity (schema
// version + per-binding fields). It does NOT re-derive the plan from
// acls.json + rules.yaml. An operator who hand-edits plan.json to add a
// binding the rules would never have produced gets exactly that binding
// back — validated, with a freshly stamped plan.sha256 that downstream
// apply/verify/delete will trust. This is intentional: operator overrides
// of the generated plan are a supported workflow. But it means a
// revalidated plan is only as trustworthy as whoever edited it; the
// fingerprint vouches for "this is the plan that was reviewed", not "this
// is the plan the rules produced". Reviewers must read the diff, not just
// confirm the checksum matches.
func Revalidate(p types.Plan) (types.Plan, error) {
	if p.SchemaVersion != "1" {
		return types.Plan{}, fmt.Errorf("revalidate: unsupported schema_version %q (expected \"1\")", p.SchemaVersion)
	}
	for i, b := range p.Bindings {
		switch b.Action {
		case types.ActionCreate, types.ActionSkipExists:
		default:
			return types.Plan{}, fmt.Errorf("revalidate: bindings[%d]: invalid action %q (allowed: CREATE, SKIP_EXISTS)", i, b.Action)
		}
		if b.Principal == "" {
			return types.Plan{}, fmt.Errorf("revalidate: bindings[%d]: principal empty", i)
		}
		if b.Role == "" {
			return types.Plan{}, fmt.Errorf("revalidate: bindings[%d]: role empty", i)
		}
		if len(b.ResourcePatterns) == 0 {
			return types.Plan{}, fmt.Errorf("revalidate: bindings[%d]: no resource_patterns", i)
		}
		for j, rp := range b.ResourcePatterns {
			if rp.Name == "" {
				return types.Plan{}, fmt.Errorf("revalidate: bindings[%d].resource_patterns[%d]: name empty", i, j)
			}
		}
	}
	return p, nil
}
