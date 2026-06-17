// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Format selects the rendering style.
type Format string

const (
	FormatText     Format = "text"
	FormatMarkdown Format = "markdown"
	FormatJSON     Format = "json"
)

// CurrentSchemaVersion is stamped into the JSON envelope's
// `schema_version` field for parity with `apply --format json` and
// `verify --format json`. Bumped when the envelope shape changes
// incompatibly. Distinct from the plan's own embedded int
// `schema_version` (in `plan.schema_version`), which versions the
// on-disk plan format.
const CurrentSchemaVersion = "1"

// jsonEnvelope wraps the plan with an envelope-level string
// `schema_version` so CI consumers can use the same fail-on-version-
// change check across apply, verify, status, and report.
type jsonEnvelope struct {
	SchemaVersion string     `json:"schema_version"`
	Plan          types.Plan `json:"plan"`
}

// Render writes p in the chosen format to w.
func Render(w io.Writer, p types.Plan, fmtType Format) error {
	switch fmtType {
	case FormatText, "":
		return renderText(w, p)
	case FormatMarkdown:
		return renderMarkdown(w, p)
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonEnvelope{
			SchemaVersion: CurrentSchemaVersion,
			Plan:          p,
		})
	default:
		return fmt.Errorf("report: unknown format %q (allowed: text, markdown, json)", fmtType)
	}
}

func renderText(w io.Writer, p types.Plan) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Plan generated at %s\n\n", p.GeneratedAt)
	fmt.Fprintln(&b, Summary(p))
	fmt.Fprintln(&b, "")

	if len(p.Bindings) > 0 {
		fmt.Fprintln(&b, "Bindings:")
		for _, bd := range p.Bindings {
			fmt.Fprintf(&b, "  [%s] %s for %s -> %s on:\n", bd.Action, bd.Role, bd.Principal, scopeOneLine(bd.Scope))
			for _, rp := range bd.ResourcePatterns {
				fmt.Fprintf(&b, "    - %s:%s (%s)\n", rp.ResourceType, rp.Name, rp.PatternType)
			}
			fmt.Fprintf(&b, "    source_acl_ids: %v\n", bd.SourceACLIDs)
		}
		fmt.Fprintln(&b, "")
	}

	if len(p.Unmapped) > 0 {
		fmt.Fprintln(&b, "Unmapped:")
		for _, u := range p.Unmapped {
			fmt.Fprintf(&b, "  - %s (source_acl_ids=%v): %s\n", u.Reason, u.SourceACLIDs, u.Detail)
		}
		fmt.Fprintln(&b, "")
	}

	if len(p.Rejected) > 0 {
		fmt.Fprintln(&b, "Rejected:")
		for _, r := range p.Rejected {
			fmt.Fprintf(&b, "  - %s (source_acl_ids=%v): %s\n", r.Reason, r.SourceACLIDs, r.Detail)
		}
		fmt.Fprintln(&b, "")
	}

	if len(p.DenyAnalysis) > 0 {
		fmt.Fprintln(&b, "DENY analysis:")
		for _, d := range p.DenyAnalysis {
			fmt.Fprintf(&b, "  - source_acl_id=%d %s", d.SourceACLID, d.Status)
			if d.CoveringRule != "" {
				fmt.Fprintf(&b, " (covered by: %s)", d.CoveringRule)
			}
			fmt.Fprintln(&b, "")
		}
		fmt.Fprintln(&b, "")
	}

	if len(p.Warnings) > 0 {
		fmt.Fprintln(&b, "Warnings:")
		for _, wn := range p.Warnings {
			fmt.Fprintf(&b, "  - [%s] %s\n", wn.Code, wn.Detail)
		}
		fmt.Fprintln(&b, "")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func renderMarkdown(w io.Writer, p types.Plan) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Plan\n\nGenerated at %s\n\n", p.GeneratedAt)
	fmt.Fprintf(&b, "%s\n\n", Summary(p))

	if len(p.Bindings) > 0 {
		fmt.Fprintln(&b, "## Bindings")
		fmt.Fprintln(&b, "")
		fmt.Fprintln(&b, "| Action | Role | Principal | Scope | Resources | Source ACL IDs |")
		fmt.Fprintln(&b, "|---|---|---|---|---|---|")
		for _, bd := range p.Bindings {
			parts := make([]string, 0, len(bd.ResourcePatterns))
			for _, rp := range bd.ResourcePatterns {
				parts = append(parts, fmt.Sprintf("%s:%s (%s)", rp.ResourceType, rp.Name, rp.PatternType))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %v |\n",
				mdCell(string(bd.Action)), mdCell(bd.Role), mdCell(bd.Principal),
				mdCell(scopeOneLine(bd.Scope)), mdCell(strings.Join(parts, ", ")), bd.SourceACLIDs)
		}
		fmt.Fprintln(&b, "")
	}

	if len(p.Unmapped) > 0 {
		fmt.Fprintln(&b, "## Unmapped")
		fmt.Fprintln(&b, "")
		for _, u := range p.Unmapped {
			fmt.Fprintf(&b, "- **%s** (source_acl_ids=%v) — %s\n", u.Reason, u.SourceACLIDs, u.Detail)
		}
		fmt.Fprintln(&b, "")
	}
	if len(p.Rejected) > 0 {
		fmt.Fprintln(&b, "## Rejected")
		fmt.Fprintln(&b, "")
		for _, r := range p.Rejected {
			fmt.Fprintf(&b, "- **%s** (source_acl_ids=%v) — %s\n", r.Reason, r.SourceACLIDs, r.Detail)
		}
		fmt.Fprintln(&b, "")
	}
	if len(p.DenyAnalysis) > 0 {
		fmt.Fprintln(&b, "## DENY analysis")
		fmt.Fprintln(&b, "")
		for _, d := range p.DenyAnalysis {
			line := fmt.Sprintf("- source_acl_id=%d → **%s**", d.SourceACLID, d.Status)
			if d.CoveringRule != "" {
				line += " (covered by: " + d.CoveringRule + ")"
			}
			fmt.Fprintln(&b, line)
		}
		fmt.Fprintln(&b, "")
	}
	if len(p.Warnings) > 0 {
		fmt.Fprintln(&b, "## Warnings")
		fmt.Fprintln(&b, "")
		for _, wn := range p.Warnings {
			fmt.Fprintf(&b, "- **[%s]** %s\n", wn.Code, wn.Detail)
		}
		fmt.Fprintln(&b, "")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// mdCell makes a string safe to place in a Markdown pipe-table cell. ACL data
// (principals, resource names) is only validated against control characters,
// so a value containing '|' would shift every following column and a reviewer
// would see a Role/Principal that doesn't match what apply will execute.
// Escape pipes and backslashes and collapse any newline to a space.
func mdCell(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ").Replace(s)
}

func scopeOneLine(s types.Scope) string {
	parts := []string{}
	if s.Organization != "" {
		parts = append(parts, "org="+s.Organization)
	}
	if s.Environment != "" {
		parts = append(parts, "env="+s.Environment)
	}
	if s.KafkaCluster != "" {
		parts = append(parts, "kafka="+s.KafkaCluster)
	}
	if s.SchemaRegistryCluster != "" {
		parts = append(parts, "sr="+s.SchemaRegistryCluster)
	}
	if s.KSQLCluster != "" {
		parts = append(parts, "ksql="+s.KSQLCluster)
	}
	if s.ConnectCluster != "" {
		parts = append(parts, "connect="+s.ConnectCluster)
	}
	return strings.Join(parts, ", ")
}
