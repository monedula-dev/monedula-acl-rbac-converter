// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/report"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func samplePlan() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{{
			ID: "rb-abcdef012345", Action: types.ActionCreate,
			Principal: "User:alice", Role: "DeveloperRead",
			Scope: types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{{
				ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
			}},
			SourceACLIDs: []int{1, 2},
		}},
		Unmapped:     []types.UnmappedEntry{},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}
}

// planWithEverything builds a Plan that exercises every section of the report.
func planWithEverything() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{
			{
				ID:        "rb-aaa",
				Action:    types.ActionCreate,
				Principal: "User:alice",
				Role:      "DeveloperRead",
				Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
				ResourcePatterns: []types.ResourcePattern{{
					ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral,
				}},
				SourceACLIDs: []int{1, 2},
			},
			{
				ID:               "rb-bbb",
				Action:           types.ActionSkipExists,
				Principal:        "User:bob",
				Role:             "DeveloperWrite",
				Scope:            types.Scope{KafkaCluster: "lkc-kafka01"},
				ResourcePatterns: []types.ResourcePattern{},
				SourceACLIDs:     []int{3},
			},
		},
		Unmapped: []types.UnmappedEntry{{
			SourceACLIDs: []int{10},
			Reason:       "NO_RULE_MATCH",
			Detail:       "operation AlterConfigs on Cluster has no matching rule",
		}},
		Rejected: []types.RejectedEntry{{
			SourceACLIDs: []int{20},
			Reason:       "DENY_PERMISSION",
			Detail:       "DENY ACL id=20 principal=User:svc resource=Topic:payments",
		}},
		Warnings: []types.Warning{{
			Code:   "MTLS_DN_PASS_THROUGH",
			Detail: "User:CN=svc,O=acme passed through verbatim",
		}},
		DenyAnalysis: []types.DenyAnalysisEntry{{
			SourceACLID:  20,
			Status:       types.DenySafeToRemove,
			CoveringRule: "",
		}, {
			SourceACLID:  21,
			Status:       types.DenyWouldGrantAccess,
			CoveringRule: "rule:Read+Describe/Topic/Allow->DeveloperRead",
		}},
	}
}

// planZeroBindings is minimal — no bindings, no unmapped/rejected/warnings.
func planZeroBindings() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings:      []types.Binding{},
		Unmapped:      []types.UnmappedEntry{},
		Rejected:      []types.RejectedEntry{},
		Warnings:      []types.Warning{},
		DenyAnalysis:  []types.DenyAnalysisEntry{},
	}
}

// ---- text format ------------------------------------------------------------

func TestRenderText_IncludesBindingDetails(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, samplePlan(), report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "DeveloperRead") {
		t.Errorf("missing role in output: %s", out)
	}
	if !strings.Contains(out, "User:alice") {
		t.Errorf("missing principal in output")
	}
}

func TestRenderText_PrincipalMappingSummary(t *testing.T) {
	p := samplePlan()
	p.Warnings = []types.Warning{{
		Code: "MTLS_DN_PASS_THROUGH", Detail: "User:CN=svc-bridge,O=acme,C=US passed through verbatim",
	}}

	var buf bytes.Buffer
	if err := report.Render(&buf, p, report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MTLS_DN_PASS_THROUGH") {
		t.Errorf("warning code not in report:\n%s", out)
	}
}

func TestRenderText_IncludesUnmappedSection(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Unmapped") {
		t.Errorf("missing 'Unmapped' section:\n%s", out)
	}
	if !strings.Contains(out, "NO_RULE_MATCH") {
		t.Errorf("missing unmapped reason:\n%s", out)
	}
}

func TestRenderText_IncludesRejectedSection(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Rejected") {
		t.Errorf("missing 'Rejected' section:\n%s", out)
	}
	if !strings.Contains(out, "DENY_PERMISSION") {
		t.Errorf("missing rejected reason:\n%s", out)
	}
}

func TestRenderText_IncludesDenyAnalysisSection(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "DENY analysis") {
		t.Errorf("missing 'DENY analysis' section:\n%s", out)
	}
	if !strings.Contains(out, "SAFE_TO_REMOVE") {
		t.Errorf("missing SAFE_TO_REMOVE in deny analysis:\n%s", out)
	}
	if !strings.Contains(out, "covered by") {
		t.Errorf("missing covering rule in deny analysis:\n%s", out)
	}
}

func TestRenderText_IncludesWarningsSection(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Warnings") {
		t.Errorf("missing 'Warnings' section:\n%s", out)
	}
	if !strings.Contains(out, "MTLS_DN_PASS_THROUGH") {
		t.Errorf("missing warning code:\n%s", out)
	}
}

func TestRenderText_SkipExistsAction_Label(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, string(types.ActionSkipExists)) {
		t.Errorf("expected SKIP_EXISTS label in output:\n%s", out)
	}
}

func TestRenderText_ZeroBindings_ProducesNonEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planZeroBindings(), report.FormatText); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if len(out) == 0 {
		t.Fatal("expected non-empty report for plan with zero bindings")
	}
	if !strings.Contains(out, "plan:") {
		t.Errorf("expected summary header in output:\n%s", out)
	}
}

// ---- markdown format --------------------------------------------------------

func TestRenderMarkdown_ContainsHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatMarkdown); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# Plan") {
		t.Errorf("markdown output missing '# Plan' header:\n%s", out)
	}
}

func TestRenderMarkdown_IncludesAllSections(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatMarkdown); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"## Bindings", "## Unmapped", "## Rejected", "## DENY analysis", "## Warnings"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing section %q:\n%s", want, out)
		}
	}
}

// TestRenderMarkdown_EscapesPipeInPrincipal pins that a '|' in a principal is
// escaped so it cannot forge extra table columns in the review artifact.
func TestRenderMarkdown_EscapesPipeInPrincipal(t *testing.T) {
	p := types.Plan{
		SchemaVersion: "1",
		Bindings: []types.Binding{{
			ID: "rb-a", Action: types.ActionCreate,
			Principal: "User:x | DeveloperRead | User:y", Role: "DeveloperRead",
			Scope:            types.Scope{KafkaCluster: "lkc-1"},
			ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
		}},
	}
	var buf bytes.Buffer
	if err := report.Render(&buf, p, report.FormatMarkdown); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), `User:x \| DeveloperRead \| User:y`) {
		t.Errorf("pipe in principal must be escaped in the markdown cell:\n%s", buf.String())
	}
}

// TestRenderMarkdown_IncludesScopeColumn pins that the bindings table shows the
// scope (blast-radius cluster), matching the text renderer.
func TestRenderMarkdown_IncludesScopeColumn(t *testing.T) {
	p := types.Plan{
		SchemaVersion: "1",
		Bindings: []types.Binding{{
			ID: "rb-a", Action: types.ActionCreate, Principal: "User:alice", Role: "DeveloperRead",
			Scope:            types.Scope{KafkaCluster: "lkc-blastradius"},
			ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}},
		}},
	}
	var buf bytes.Buffer
	if err := report.Render(&buf, p, report.FormatMarkdown); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Scope") || !strings.Contains(out, "lkc-blastradius") {
		t.Errorf("markdown bindings table should include scope; got:\n%s", out)
	}
}

func TestRenderMarkdown_ZeroBindings_ProducesNonEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planZeroBindings(), report.FormatMarkdown); err != nil {
		t.Fatalf("render: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty markdown report for zero-binding plan")
	}
}

// ---- JSON format ------------------------------------------------------------

func TestRenderJSON_ParsesBackToPlan(t *testing.T) {
	p := planWithEverything()
	var buf bytes.Buffer
	if err := report.Render(&buf, p, report.FormatJSON); err != nil {
		t.Fatalf("render: %v", err)
	}
	// The JSON envelope wraps the plan with `schema_version: "1"` for
	// parity with apply/verify --format json. The plan is in the `plan`
	// field.
	var env struct {
		SchemaVersion string     `json:"schema_version"`
		Plan          types.Plan `json:"plan"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("JSON output does not parse: %v\noutput:\n%s", err, buf.String())
	}
	if env.SchemaVersion != "1" {
		t.Errorf("schema_version: got %q, want %q", env.SchemaVersion, "1")
	}
	got := env.Plan
	if len(got.Bindings) != len(p.Bindings) {
		t.Errorf("expected %d bindings, got %d", len(p.Bindings), len(got.Bindings))
	}
	if len(got.Unmapped) != len(p.Unmapped) {
		t.Errorf("expected %d unmapped, got %d", len(p.Unmapped), len(got.Unmapped))
	}
	if len(got.Rejected) != len(p.Rejected) {
		t.Errorf("expected %d rejected, got %d", len(p.Rejected), len(got.Rejected))
	}
	if len(got.DenyAnalysis) != len(p.DenyAnalysis) {
		t.Errorf("expected %d deny_analysis, got %d", len(p.DenyAnalysis), len(got.DenyAnalysis))
	}
}

// TestRenderJSON_ValidatesAgainstSchema asserts the report JSON envelope
// validates against schemas/report.v1.json. The schema enforces
// {schema_version: "1", plan: <object>}; the inner plan is left open
// (callers wanting strict validation should call schema.ValidatePlan on
// the unwrapped plan separately).
func TestRenderJSON_ValidatesAgainstSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Render(&buf, planWithEverything(), report.FormatJSON); err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := schema.ValidateReportOutput(buf.Bytes()); err != nil {
		t.Errorf("report JSON should validate against report.v1.json:\n%v\noutput:\n%s", err, buf.String())
	}
}

// ---- format dispatch --------------------------------------------------------

func TestRender_AllFormats_NoError(t *testing.T) {
	p := planWithEverything()
	for _, f := range []report.Format{report.FormatText, report.FormatMarkdown, report.FormatJSON} {
		var buf bytes.Buffer
		if err := report.Render(&buf, p, f); err != nil {
			t.Errorf("format %q: unexpected error: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("format %q: output is empty", f)
		}
	}
}

func TestRender_UnknownFormat_ReturnsError(t *testing.T) {
	var buf bytes.Buffer
	err := report.Render(&buf, planZeroBindings(), report.Format("xml"))
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "xml") {
		t.Errorf("error should mention the bad format: %v", err)
	}
}

// ---- Summary ----------------------------------------------------------------

func TestSummary_TerseOneLiner(t *testing.T) {
	p := samplePlan()
	got := report.Summary(p)
	if !strings.Contains(got, "1 binding") {
		t.Errorf("summary missing binding count: %q", got)
	}
	if !strings.Contains(got, "0 unmapped") {
		t.Errorf("summary missing unmapped count: %q", got)
	}
}

func TestSummary_IncludesAllCounts(t *testing.T) {
	p := planWithEverything()
	got := report.Summary(p)
	for _, want := range []string{"2 binding", "1 unmapped", "1 rejected", "1 warning"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q: %q", want, got)
		}
	}
}

func TestSummary_IncludesDenyCounts(t *testing.T) {
	p := planWithEverything()
	got := report.Summary(p)
	if !strings.Contains(got, "DENY") {
		t.Errorf("summary should include DENY stats when deny_analysis is non-empty: %q", got)
	}
	if !strings.Contains(got, "1 safe") {
		t.Errorf("summary should report 1 safe: %q", got)
	}
	if !strings.Contains(got, "1 would-grant") {
		t.Errorf("summary should report 1 would-grant: %q", got)
	}
}

func TestSummary_ZeroBindings(t *testing.T) {
	got := report.Summary(planZeroBindings())
	if !strings.Contains(got, "0 binding") {
		t.Errorf("expected '0 binding' in summary: %q", got)
	}
	if !strings.Contains(got, "0 unmapped") {
		t.Errorf("expected '0 unmapped' in summary: %q", got)
	}
	if !strings.Contains(got, "0 rejected") {
		t.Errorf("expected '0 rejected' in summary: %q", got)
	}
	if !strings.Contains(got, "0 warning") {
		t.Errorf("expected '0 warning' in summary: %q", got)
	}
	if strings.Contains(got, "DENY") {
		t.Errorf("DENY section should be absent with empty deny_analysis: %q", got)
	}
}
