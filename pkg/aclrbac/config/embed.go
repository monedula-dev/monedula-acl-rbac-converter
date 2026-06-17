// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config

import "embed"

//go:embed defaults.yaml
var defaultRulesFS embed.FS

// DefaultRulesYAML returns the embedded default mapping rules verbatim.
// `monedula-acl-rbac rules show` writes this to stdout; the planner merges it
// with any --rules overrides.
func DefaultRulesYAML() ([]byte, error) {
	return defaultRulesFS.ReadFile("defaults.yaml")
}
