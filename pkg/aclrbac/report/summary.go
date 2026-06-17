// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package report renders a RoleBindingPlan to text/markdown/json for human
// review. It is the source of `report.txt` written by `plan` and the
// re-printing target of the standalone `report` subcommand.
package report

import (
	"fmt"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Summary returns a one-line summary suitable for `plan`'s stderr output.
func Summary(p types.Plan) string {
	denyCounts := map[types.DenyAnalysisStatus]int{}
	for _, d := range p.DenyAnalysis {
		denyCounts[d.Status]++
	}
	s := fmt.Sprintf(
		"plan: %d binding(s), %d unmapped, %d rejected, %d warning(s)",
		len(p.Bindings), len(p.Unmapped), len(p.Rejected), len(p.Warnings),
	)
	if len(p.DenyAnalysis) > 0 {
		s += fmt.Sprintf("; DENY: %d safe / %d would-grant / %d unknown",
			denyCounts[types.DenySafeToRemove],
			denyCounts[types.DenyWouldGrantAccess],
			denyCounts[types.DenyUnknown],
		)
	}
	return s
}
