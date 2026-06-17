// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package emit renders a RoleBindingPlan into the format chosen via
// `--format` on the `emit` subcommand. Each concrete format is a
// subpackage; this file holds the shared interface and ordering helpers.
package emit

import (
	"io"
	"sort"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// SanitizeComment makes a plan-derived string safe to interpolate into a
// single-line shell `#` comment. A comment only neutralizes metacharacters up
// to the next newline, so a value containing a newline (reachable via
// hand-edited plan.json or via group/transactional ids and DN principals from
// the source ACLs) would terminate the comment and turn the remainder into an
// executable line. Collapse CR/LF to spaces so the comment stays one line.
func SanitizeComment(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// Emitter renders a Plan into one of: script | cfk | mds-curl.
type Emitter interface {
	// Name returns the value used in --format.
	Name() string
	// Emit writes the rendered artifact to w. Returns the number of bindings
	// it actually emitted (CREATE rows only; SKIP_EXISTS are commented in).
	Emit(w io.Writer, plan types.Plan) (int, error)
}

// OrderedBindings returns plan.Bindings sorted for deterministic output:
//   - CREATE actions first, then SKIP_EXISTS
//   - within each action, by Binding.ID ascending
func OrderedBindings(in []types.Binding) []types.Binding {
	out := append([]types.Binding(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].ID < out[j].ID
	})
	return out
}
