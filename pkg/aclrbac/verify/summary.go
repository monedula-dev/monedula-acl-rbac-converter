// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package verify

import (
	"encoding/json"
	"fmt"
	"io"
)

// Format chooses how Summary renders to its writer. Mirrors apply.Format
// so operators get a consistent shape across the two commands.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Counts aggregates Result statuses for the JSON envelope and the
// text one-liner. The effective_* fields are always present (they remain
// zero in bindings-exist mode); the binding_* fields are omitted unless
// populated, since they only carry meaning in bindings-exist mode.
type Counts struct {
	Total            int `json:"total"`
	EffectiveOK      int `json:"effective_ok"`
	EffectiveMissing int `json:"effective_missing"`
	EffectiveUnknown int `json:"effective_unknown"`
	BindingExists    int `json:"binding_exists,omitempty"`
	BindingMissing   int `json:"binding_missing,omitempty"`
	BindingUnknown   int `json:"binding_unknown,omitempty"`
}

// CurrentSchemaVersion is the version string stamped into the JSON
// envelope's `schema_version` field. Bumped when the envelope shape
// changes in a way that breaks downstream consumers.
const CurrentSchemaVersion = "1"

// Summary is the verify outcome envelope.
type Summary struct {
	SchemaVersion string `json:"schema_version"`
	// PlanSHA256 binds this verify run to the exact plan.json it checked.
	// delete-acls / delete-deny-acls / delete-deny-one refuse to run if it
	// does not match the plan being deleted against, closing the window
	// where a stale verify.json vouches for a different (re-generated)
	// plan. Stamped by Run from Options.PlanPath.
	PlanSHA256 string `json:"plan_sha256"`
	// Mode records the verification strategy ("effective" or
	// "bindings-exist"). Omitted when unset so library callers that build
	// a Summary directly aren't forced to populate it.
	Mode    string   `json:"mode,omitempty"`
	Results []Result `json:"results"`
	Counts  Counts   `json:"counts"`
}

// AggregateCounts derives Counts from Results and returns the result.
// Run() calls this once at the end before rendering. Non-effective
// statuses (BINDING_EXISTS / BINDING_MISSING from bindings-exist mode)
// are still counted in Total but do not feed the effective_* fields.
func (s Summary) AggregateCounts() Counts {
	var c Counts
	for _, r := range s.Results {
		c.Total++
		switch r.Status {
		case StatusEffectiveOK:
			c.EffectiveOK++
		case StatusEffectiveMissing:
			c.EffectiveMissing++
		case StatusEffectiveUnknown:
			c.EffectiveUnknown++
		case StatusBindingExists:
			c.BindingExists++
		case StatusBindingMissing:
			c.BindingMissing++
		case StatusBindingUnknown:
			c.BindingUnknown++
		}
	}
	return c
}

// WriteText renders a one-line human-readable summary.
//
// The two verify modes populate disjoint counters: `--mode effective` fills
// EffectiveOK / EffectiveMissing / EffectiveUnknown; `--mode bindings-exist`
// fills BindingExists / BindingMissing. Render whichever the results actually
// used so a healthy bindings-exist run doesn't print the misleading
// `verify: 0 EFFECTIVE_OK, 0 missing, 0 unknown (N total)`. Empty results
// fall through to the effective line (the default mode).
func (s Summary) WriteText(w io.Writer) error {
	c := s.AggregateCounts()
	bindingsExistMode := (c.BindingExists+c.BindingMissing+c.BindingUnknown) > 0 &&
		(c.EffectiveOK+c.EffectiveMissing+c.EffectiveUnknown) == 0
	if bindingsExistMode {
		_, err := fmt.Fprintf(w, "verify: %d bindings present, %d missing, %d unknown (%d total)\n",
			c.BindingExists, c.BindingMissing, c.BindingUnknown, c.Total)
		return err
	}
	_, err := fmt.Fprintf(w, "verify: %d EFFECTIVE_OK, %d missing, %d unknown (%d total)\n",
		c.EffectiveOK, c.EffectiveMissing, c.EffectiveUnknown, c.Total)
	return err
}

// WriteJSON renders Summary as a single JSON object, with Counts
// populated and schema_version stamped, for CI/CD consumption.
// The envelope is described by schemas/verify-summary.v1.json.
func (s Summary) WriteJSON(w io.Writer) error {
	s.SchemaVersion = CurrentSchemaVersion
	s.Counts = s.AggregateCounts()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
