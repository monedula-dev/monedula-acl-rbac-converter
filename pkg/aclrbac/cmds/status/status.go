// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package status implements `monedula-acl-rbac status`.
package status

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

// Format selects the output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Run writes a summary of `runDir` to `w`.
func Run(w io.Writer, runDir string, format Format) error {
	rep := compile(runDir)
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	default:
		return renderText(w, runDir, rep)
	}
}

// CurrentSchemaVersion is stamped into the JSON `schema_version` field
// for parity with `apply --format json` and `verify --format json`. Bump
// when the envelope shape changes incompatibly.
const CurrentSchemaVersion = "1"

// Report is the data emitted by `status`.
type Report struct {
	SchemaVersion string  `json:"schema_version"`
	RunDir        string  `json:"run_dir"`
	Extract       *step   `json:"extract,omitempty"`
	Plan          *step   `json:"plan,omitempty"`
	Apply         *step   `json:"apply,omitempty"`
	Verify        *step   `json:"verify,omitempty"`
	Delete        *step   `json:"delete,omitempty"`
	DenyDel       *step   `json:"delete_deny,omitempty"`
	Lock          *string `json:"lock,omitempty"`
}

type step struct {
	Present bool        `json:"present"`
	Detail  interface{} `json:"detail,omitempty"`
}

func compile(runDir string) Report {
	r := Report{SchemaVersion: CurrentSchemaVersion, RunDir: runDir}

	if set, err := rundir.ReadACLs(filepath.Join(runDir, "acls.json")); err == nil {
		r.Extract = &step{Present: true, Detail: map[string]interface{}{
			"acl_count": len(set.ACLs),
			"source":    set.Source.Type,
		}}
	}
	planPath := filepath.Join(runDir, "plan.json")
	if plan, err := rundir.ReadPlan(planPath); err == nil {
		ckErr := rundir.VerifyChecksum(planPath)
		r.Plan = &step{Present: true, Detail: map[string]interface{}{
			"bindings":    len(plan.Bindings),
			"unmapped":    len(plan.Unmapped),
			"rejected":    len(plan.Rejected),
			"checksum_ok": ckErr == nil,
		}}
	}
	if _, err := os.Stat(filepath.Join(runDir, "apply.log")); err == nil {
		r.Apply = &step{Present: true}
	}
	if data, err := os.ReadFile(filepath.Join(runDir, "verify.json")); err == nil {
		// Envelope-only — bare-array verify.json (any earlier dev shape)
		// is no longer accepted. Mirror cmd_delete.go::readVerify: surface
		// an "unreadable" detail rather than rendering fake-zero counts,
		// so the operator can't mistake a stale file for a healthy run.
		var sum verify.Summary
		jerr := json.Unmarshal(data, &sum)
		if jerr != nil || sum.Results == nil {
			r.Verify = &step{Present: true, Detail: "(unreadable: re-run 'verify' to regenerate)"}
		} else {
			counts := sum.AggregateCounts()
			r.Verify = &step{Present: true, Detail: map[string]int{
				"total":             counts.Total,
				"effective_ok":      counts.EffectiveOK,
				"effective_missing": counts.EffectiveMissing,
				"effective_unknown": counts.EffectiveUnknown,
			}}
		}
	}
	if _, err := os.Stat(filepath.Join(runDir, "delete.log")); err == nil {
		r.Delete = &step{Present: true}
	}
	if _, err := os.Stat(filepath.Join(runDir, "delete-deny.log")); err == nil {
		r.DenyDel = &step{Present: true}
	}
	if data, err := os.ReadFile(filepath.Join(runDir, ".lock")); err == nil {
		s := string(data)
		r.Lock = &s
	}
	return r
}

func renderText(w io.Writer, runDir string, r Report) error {
	fmt.Fprintf(w, "Run directory: %s\n\n", runDir)
	one := func(name string, s *step) {
		if s == nil || !s.Present {
			fmt.Fprintf(w, "%-18s NOT RUN\n", name+":")
			return
		}
		// Render Detail as "k1=v1, k2=v2 …" (sorted keys) instead of Go's
		// default `%v` over an `interface{}` map, which prints
		// `map[acl_count:500 source:json]` — a flagship `status` command
		// shouldn't show internal map syntax at v1.0.
		fmt.Fprintf(w, "%-18s %s\n", name+":", renderDetail(s.Detail))
	}
	one("extract", r.Extract)
	one("plan", r.Plan)
	one("apply", r.Apply)
	// verify gets a bespoke renderer so the line matches the README
	// sample shape: "N EFFECTIVE_OK, M missing, K unknown (T total)".
	if r.Verify == nil || !r.Verify.Present {
		fmt.Fprintf(w, "%-18s NOT RUN\n", "verify:")
	} else if d, ok := r.Verify.Detail.(map[string]int); ok {
		fmt.Fprintf(w, "%-18s %d EFFECTIVE_OK, %d missing, %d unknown (%d total)\n",
			"verify:", d["effective_ok"], d["effective_missing"], d["effective_unknown"], d["total"])
	} else {
		fmt.Fprintf(w, "%-18s %v\n", "verify:", r.Verify.Detail)
	}
	one("delete-acls", r.Delete)
	one("delete-deny-acls", r.DenyDel)
	if r.Lock != nil {
		fmt.Fprintf(w, "lock:              %s", *r.Lock)
	} else {
		fmt.Fprintln(w, "lock:              none")
	}
	return nil
}

// renderDetail formats a step.Detail for the text output. The detail is
// usually a `map[string]interface{}` produced by `compile`, so we render it
// as a stable comma-separated `key=value` list (sorted keys) rather than
// Go's `%v` over a map, which prints the not-very-friendly
// `map[acl_count:500 source:json]`. Non-map details (or nil) fall back to
// `%v` — they're already simple values.
func renderDetail(d interface{}) string {
	m, ok := d.(map[string]interface{})
	if !ok {
		if d == nil {
			return ""
		}
		return fmt.Sprintf("%v", d)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(m))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, ", ")
}
