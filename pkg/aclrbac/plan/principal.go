// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"fmt"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
)

// PrincipalResult is the outcome of mapping one source principal through
// principals.yaml.
type PrincipalResult struct {
	// Resolved is the MDS-side principal to use (User:... or Group:...).
	Resolved string
	// PassedThrough is true when the source principal had no explicit
	// mapping and Fallback=pass-through let it through verbatim.
	PassedThrough bool
	// LooksLikeMTLSDN flags pass-through principals whose body resembles a
	// distinguished name (e.g., "User:CN=alice,O=acme,C=US"). The planner
	// emits a WARN for these.
	LooksLikeMTLSDN bool
}

// MapPrincipal resolves a single source principal. Returns an error if the
// principal is unmapped and fallback=fail.
func MapPrincipal(source string, cfg config.Principals) (PrincipalResult, error) {
	if mapped, ok := cfg.Mappings[source]; ok {
		return PrincipalResult{Resolved: mapped}, nil
	}
	if cfg.Fallback == config.PrincipalFallbackFail {
		return PrincipalResult{}, fmt.Errorf("principal %q has no mapping and fallback=fail", source)
	}
	return PrincipalResult{
		Resolved:        source,
		PassedThrough:   true,
		LooksLikeMTLSDN: looksLikeMTLSDN(source),
	}, nil
}

// looksLikeMTLSDN returns true if the principal body looks like an X.509
// distinguished name (DN). The heuristic matches "User:CN=..." or any value
// containing `CN=` and at least one of `O=`, `OU=`, `C=`.
func looksLikeMTLSDN(p string) bool {
	body := p
	if i := strings.Index(body, ":"); i >= 0 {
		body = body[i+1:]
	}
	if !strings.Contains(body, "CN=") {
		return false
	}
	return strings.Contains(body, "O=") || strings.Contains(body, "OU=") || strings.Contains(body, "C=")
}
