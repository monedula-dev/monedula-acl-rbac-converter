// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package apply

import (
	"encoding/json"
	"fmt"
	"io"
)

// Format chooses how Summary renders to its writer.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Status is the per-binding outcome.
type Status string

const (
	StatusCreated    Status = "CREATED"
	StatusSkipExists Status = "SKIP_EXISTS"
	StatusFailed     Status = "FAILED"
	// WOULD_* statuses are emitted by DryRun. They live alongside the
	// real-apply statuses on Summary so dry-run output uses the same
	// JSON shape (Bindings + Counts), letting CI parsers branch on
	// status values rather than parsing two different envelopes.
	StatusWouldCreate Status = "WOULD_CREATE"
	StatusWouldSkip   Status = "WOULD_SKIP"
)

// BindingResult is one row in the apply summary.
type BindingResult struct {
	BindingID string `json:"binding_id"`
	Principal string `json:"principal"`
	Role      string `json:"role"`
	Status    Status `json:"status"`
	Error     string `json:"error,omitempty"`
}

// Counts aggregates BindingResult statuses. WouldCreate / WouldSkip
// are populated only by DryRun summaries; they're kept separate from
// Created / SkipExists so the JSON consumer can tell a preview from a
// real run unambiguously.
type Counts struct {
	Total       int `json:"total"`
	Created     int `json:"created"`
	SkipExists  int `json:"skip_exists"`
	Failed      int `json:"failed"`
	WouldCreate int `json:"would_create,omitempty"`
	WouldSkip   int `json:"would_skip,omitempty"`
}

// CurrentSchemaVersion is the version string stamped into the JSON
// envelope's `schema_version` field. Bumped when the envelope shape
// changes in a way that breaks downstream consumers.
const CurrentSchemaVersion = "1"

// Summary is the apply outcome envelope.
type Summary struct {
	SchemaVersion string          `json:"schema_version"`
	Bindings      []BindingResult `json:"bindings"`
	Counts        Counts          `json:"counts"`
}

// AggregateCounts derives Counts from Bindings and returns the result.
// Run() calls this once at the end before rendering.
func (s Summary) AggregateCounts() Counts {
	var c Counts
	for _, b := range s.Bindings {
		c.Total++
		switch b.Status {
		case StatusCreated:
			c.Created++
		case StatusSkipExists:
			c.SkipExists++
		case StatusFailed:
			c.Failed++
		case StatusWouldCreate:
			c.WouldCreate++
		case StatusWouldSkip:
			c.WouldSkip++
		}
	}
	return c
}

// isDryRun returns true when any binding carries a WOULD_* status,
// telling WriteText to switch its prefix and verbs. We don't carry a
// separate "this is a dry run" flag because the status values are
// authoritative: a row's status describes what actually happened (or
// would have).
func (s Summary) isDryRun() bool {
	for _, b := range s.Bindings {
		if b.Status == StatusWouldCreate || b.Status == StatusWouldSkip {
			return true
		}
	}
	return false
}

// WriteText renders a one-paragraph human-readable summary plus any
// FAILED lines with their error messages. Dry-run summaries (rows with
// WOULD_* statuses) get a "(dry-run)" prefix and "would create" /
// "would skip" verbs to make stdout unambiguous; CI scripts can branch
// on the prefix or on the WOULD_* status values in JSON mode.
func (s Summary) WriteText(w io.Writer) error {
	c := s.AggregateCounts()
	if s.isDryRun() {
		if _, err := fmt.Fprintf(w, "apply (dry-run): %d would create, %d would skip (%d total)\n",
			c.WouldCreate, c.WouldSkip, c.Total); err != nil {
			return err
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "apply: %d created, %d skipped, %d failed (%d total)\n",
		c.Created, c.SkipExists, c.Failed, c.Total); err != nil {
		return err
	}
	for _, b := range s.Bindings {
		if b.Status == StatusFailed {
			if _, err := fmt.Fprintf(w, "FAILED %s (%s -> %s): %s\n", b.BindingID, b.Principal, b.Role, b.Error); err != nil {
				return err
			}
		}
	}
	return nil
}

// WriteJSON renders Summary as a single JSON object, with Counts
// populated and schema_version stamped, for CI/CD consumption.
// The envelope is described by schemas/apply-summary.v1.json.
func (s Summary) WriteJSON(w io.Writer) error {
	s.SchemaVersion = CurrentSchemaVersion
	s.Counts = s.AggregateCounts()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
