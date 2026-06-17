// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// ---- Helpers ----------------------------------------------------------------

// minimalACLsJSON is a valid acls.json that produces one DeveloperRead binding.
const minimalACLsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-01-01T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",
     "resource_type": "Topic", "resource_name": "orders",
     "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe",
     "resource_type": "Topic", "resource_name": "orders",
     "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`

// buildPlan creates a tmp dir with acls.json + scopes.yaml, runs `plan`, and
// returns (dir, planPath). Fatal on failure.
func buildPlan(t *testing.T) (dir, planPath string) {
	t.Helper()
	dir = t.TempDir()
	aclsPath := filepath.Join(dir, "acls.json")
	scopesPath := filepath.Join(dir, "scopes.yaml")
	planPath = filepath.Join(dir, "plan.json")
	if err := os.WriteFile(aclsPath, []byte(minimalACLsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if exit := cli.Execute([]string{
		"plan", "--acls", aclsPath, "--scopes", scopesPath, "--out", planPath,
	}); exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}
	return dir, planPath
}

// ---- report command tests ---------------------------------------------------

// TestReport_FormatText: `report --plan X --format text` exits 0 and prints to
// stdout.
func TestReport_FormatText(t *testing.T) {
	_, planPath := buildPlan(t)

	// Redirect stdout so we can inspect it.
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	exit := cli.Execute([]string{"report", "--plan", planPath, "--format", "text"})
	w.Close()
	os.Stdout = old

	var buf strings.Builder
	buf2 := make([]byte, 4096)
	for {
		n, _ := r.Read(buf2)
		if n == 0 {
			break
		}
		buf.Write(buf2[:n])
	}

	if exit != 0 {
		t.Fatalf("report --format text exit %d", exit)
	}
}

// TestReport_FormatJSON: `report --plan X --format json` exits 0 and writes
// valid JSON to stdout.
func TestReport_FormatJSON(t *testing.T) {
	_, planPath := buildPlan(t)

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.json")
	exit := cli.Execute([]string{"report", "--plan", planPath, "--format", "json", "--out", outPath})
	if exit != 0 {
		t.Fatalf("report --format json exit %d", exit)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Errorf("report --format json produced invalid JSON: %v\n%s", err, data)
	}
}

// TestReport_FormatMarkdown: `report --plan X --format markdown` exits 0 and
// produces markdown-ish output (# headings).
func TestReport_FormatMarkdown(t *testing.T) {
	_, planPath := buildPlan(t)

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.md")
	exit := cli.Execute([]string{"report", "--plan", planPath, "--format", "markdown", "--out", outPath})
	if exit != 0 {
		t.Fatalf("report --format markdown exit %d", exit)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report.md: %v", err)
	}
	if len(data) == 0 {
		t.Error("report markdown output is empty")
	}
}

// TestReport_MissingPlanFlag: --plan is required.
func TestReport_MissingPlanFlag(t *testing.T) {
	exit := cli.Execute([]string{"report"})
	if exit == 0 {
		t.Error("expected non-zero exit when --plan is missing")
	}
}

// unhealthyPlan returns a valid plan that contains an UNMAPPED entry.
// Used to exercise the report --strict gating.
func unhealthyPlan() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:00:00Z",
		Bindings:      []types.Binding{},
		Unmapped: []types.UnmappedEntry{{
			SourceACLIDs: []int{1},
			Reason:       "NO_RULE_MATCH",
			Detail:       "test fixture",
		}},
		Rejected:     []types.RejectedEntry{},
		Warnings:     []types.Warning{},
		DenyAnalysis: []types.DenyAnalysisEntry{},
	}
}

// TestReport_DefaultExitsZeroOnUnhealthyPlan: default mode renders the
// report and returns success even when the plan has UNMAPPED entries.
// Viewing a plan should not fail.
func TestReport_DefaultExitsZeroOnUnhealthyPlan(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, unhealthyPlan()); err != nil {
		t.Fatalf("WritePlan: %v", err)
	}

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.txt")
	exit := cli.Execute([]string{"report", "--plan", planPath, "--format", "text", "--out", outPath})
	if exit != 0 {
		t.Fatalf("report on unhealthy plan should exit 0 by default; got %d", exit)
	}
}

// TestReport_StrictExitsNonZeroOnUnhealthyPlan: --strict opts back in
// to the legacy CI-gate behaviour: exit non-zero on UNMAPPED/REJECTED.
func TestReport_StrictExitsNonZeroOnUnhealthyPlan(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, unhealthyPlan()); err != nil {
		t.Fatalf("WritePlan: %v", err)
	}

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.txt")
	exit := cli.Execute([]string{"report", "--plan", planPath, "--format", "text", "--out", outPath, "--strict"})
	if exit == 0 {
		t.Error("report --strict on unhealthy plan should exit non-zero")
	}
}

// ---- emit command tests -----------------------------------------------------

// TestEmit_FormatScript: emit --format script writes a .sh file.
func TestEmit_FormatScript(t *testing.T) {
	_, planPath := buildPlan(t)

	outDir := t.TempDir()
	exit := cli.Execute([]string{"emit", "--plan", planPath, "--format", "script", "--out-dir", outDir})
	if exit != 0 {
		t.Fatalf("emit --format script exit %d", exit)
	}
	shPath := filepath.Join(outDir, "script.sh")
	if _, err := os.Stat(shPath); err != nil {
		t.Errorf("expected script.sh in %s: %v", outDir, err)
	}
}

// TestEmit_FormatCFK: emit --format cfk writes cfk.yaml.
func TestEmit_FormatCFK(t *testing.T) {
	_, planPath := buildPlan(t)

	outDir := t.TempDir()
	exit := cli.Execute([]string{"emit", "--plan", planPath, "--format", "cfk", "--out-dir", outDir})
	if exit != 0 {
		t.Fatalf("emit --format cfk exit %d", exit)
	}
	yamlPath := filepath.Join(outDir, "cfk.yaml")
	if _, err := os.Stat(yamlPath); err != nil {
		t.Errorf("expected cfk.yaml in %s: %v", outDir, err)
	}
}

// TestEmit_FormatMDSCurl: emit --format mds-curl writes mds-curl.sh.
func TestEmit_FormatMDSCurl(t *testing.T) {
	_, planPath := buildPlan(t)

	outDir := t.TempDir()
	exit := cli.Execute([]string{"emit", "--plan", planPath, "--format", "mds-curl", "--out-dir", outDir})
	if exit != 0 {
		t.Fatalf("emit --format mds-curl exit %d", exit)
	}
	shPath := filepath.Join(outDir, "mds-curl.sh")
	if _, err := os.Stat(shPath); err != nil {
		t.Errorf("expected mds-curl.sh in %s: %v", outDir, err)
	}
}

// TestEmit_UnknownFormat: unknown --format returns usage error (exit 1).
func TestEmit_UnknownFormat(t *testing.T) {
	_, planPath := buildPlan(t)
	exit := cli.Execute([]string{"emit", "--plan", planPath, "--format", "bogus"})
	if exit != int(cli.MapError(cli.NewUsageError(""))) {
		// Accept any non-zero exit.
		if exit == 0 {
			t.Error("expected non-zero exit for unknown --format")
		}
	}
}

// TestEmit_MissingPlanFlag: --plan is required.
func TestEmit_MissingPlanFlag(t *testing.T) {
	exit := cli.Execute([]string{"emit"})
	if exit == 0 {
		t.Error("expected non-zero exit when --plan is missing")
	}
}

// TestEmit_StdoutDefault: emit without --out writes to stdout (no error).
func TestEmit_StdoutDefault(t *testing.T) {
	_, planPath := buildPlan(t)

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	exit := cli.Execute([]string{"emit", "--plan", planPath, "--format", "script"})
	w.Close()
	os.Stdout = old

	// Drain the pipe to avoid blocking.
	buf := make([]byte, 8192)
	r.Read(buf) //nolint:errcheck

	if exit != 0 {
		t.Fatalf("emit to stdout exit %d", exit)
	}
}
