// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// BindingID computes the stable identifier emitted as metadata.name in CFK
// output and as Binding.ID in plan.json. Format: `rb-<12 hex chars of SHA-256>`.
//
// Inputs to the hash are canonicalised so re-emitting an identical binding
// produces the same ID (resource patterns are sorted, fields lowercased
// where case is meaningless). `salt` is included verbatim — pass "" for the
// default scheme; pass the `--cfk-name-salt` value to disambiguate from a
// collision.
func BindingID(b types.Binding, salt string) string {
	type canonical struct {
		Principal        string                  `json:"principal"`
		Role             string                  `json:"role"`
		Scope            types.Scope             `json:"scope"`
		ResourcePatterns []types.ResourcePattern `json:"resource_patterns"`
		Salt             string                  `json:"salt,omitempty"`
	}

	patterns := make([]types.ResourcePattern, len(b.ResourcePatterns))
	copy(patterns, b.ResourcePatterns)
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].ResourceType != patterns[j].ResourceType {
			return patterns[i].ResourceType < patterns[j].ResourceType
		}
		if patterns[i].PatternType != patterns[j].PatternType {
			return patterns[i].PatternType < patterns[j].PatternType
		}
		return patterns[i].Name < patterns[j].Name
	})

	c := canonical{
		Principal: b.Principal,
		// GOTCHA: Role is lowercased into the hash so that "DeveloperRead"
		// and "developerread" produce the same BindingID. The comparison
		// sites that match a planned binding against an MDS reply, however,
		// are CASE-SENSITIVE on Role (apply/apply.go alreadyHas and
		// verify/bindings_exist.go matched). That asymmetry means a binding
		// emitted with Role "DeveloperRead" and an MDS reply carrying
		// "developerread" would match by ID but fail the content match —
		// apply would try to (re)create it and verify would report
		// BINDING_MISSING. The current rule set only ever emits canonical
		// Confluent role names, so this never triggers in practice; it is
		// documented here as a latent gotcha for anyone adding roles or a
		// custom role source. If that changes, either lowercase Role at the
		// comparison sites too, or stop lowercasing it here.
		Role:             strings.ToLower(b.Role),
		Scope:            b.Scope,
		ResourcePatterns: patterns,
		Salt:             salt,
	}

	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return "rb-" + hex.EncodeToString(sum[:])[:12]
}
