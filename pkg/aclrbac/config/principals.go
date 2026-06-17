// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PrincipalFallback is what to do for a principal not listed in the mapping.
type PrincipalFallback string

const (
	// PrincipalFallbackPassThrough emits the source principal verbatim with a
	// WARN if it looks like an mTLS DN. This is the default.
	PrincipalFallbackPassThrough PrincipalFallback = "pass-through"
	// PrincipalFallbackFail treats any unmapped principal as a hard error.
	PrincipalFallbackFail PrincipalFallback = "fail"
)

// Principals holds the parsed principals.yaml.
type Principals struct {
	Mappings map[string]string
	Fallback PrincipalFallback
}

// ParsePrincipals parses a principals.yaml document. An empty document is
// valid and yields pass-through fallback with no mappings.
func ParsePrincipals(data []byte) (Principals, error) {
	var raw struct {
		Principals map[string]string `yaml:"principals"`
		Fallback   string            `yaml:"fallback"`
	}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return Principals{}, fmt.Errorf("parse principals.yaml: %w", err)
		}
	}
	fallback := PrincipalFallbackPassThrough
	switch raw.Fallback {
	case "", "pass-through":
		// pass-through (default)
	case "fail":
		fallback = PrincipalFallbackFail
	default:
		return Principals{}, fmt.Errorf("parse principals.yaml: unknown fallback %q (allowed: pass-through, fail)", raw.Fallback)
	}
	mappings := raw.Principals
	if mappings == nil {
		mappings = map[string]string{}
	}
	// Reject empty mapping targets: a "" value would make MapPrincipal resolve
	// to an empty principal and the planner would emit a binding with no
	// principal. Source keys may legitimately be any non-empty string.
	for src, dst := range mappings {
		if strings.TrimSpace(dst) == "" {
			return Principals{}, fmt.Errorf("parse principals.yaml: mapping for %q has an empty target principal", src)
		}
	}
	return Principals{
		Mappings: mappings,
		Fallback: fallback,
	}, nil
}
