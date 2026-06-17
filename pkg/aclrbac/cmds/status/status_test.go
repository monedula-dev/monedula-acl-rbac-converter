// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package status_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/status"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

func TestRun_PartialRunDir(t *testing.T) {
	dir := t.TempDir()
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs:          []types.ACLRow{{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), set); err != nil {
		t.Fatal(err)
	}
	plan := types.Plan{
		SchemaVersion: "1", GeneratedAt: "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{{ID: "rb-abcdef012345", Action: types.ActionCreate, Principal: "User:alice", Role: "DeveloperRead", Scope: types.Scope{KafkaCluster: "lkc-kafka01"}, ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}}, SourceACLIDs: []int{1}}},
		Unmapped: []types.UnmappedEntry{}, Rejected: []types.RejectedEntry{}, Warnings: []types.Warning{}, DenyAnalysis: []types.DenyAnalysisEntry{},
	}
	if err := rundir.WritePlan(filepath.Join(dir, "plan.json"), plan); err != nil {
		t.Fatal(err)
	}
	_ = rundir.WriteChecksum(filepath.Join(dir, "plan.json"))

	var buf bytes.Buffer
	if err := status.Run(&buf, dir, status.FormatText); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"extract:", "plan:", "apply:", "NOT RUN"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRun_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	_ = status.Run(&buf, dir, status.FormatJSON)
	var v map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Errorf("output should be JSON: %v", err)
	}
	// CI consumers fail-fast if schema_version changes; matches
	// apply/verify --format json convention.
	if got, want := v["schema_version"], "1"; got != want {
		t.Errorf("schema_version: got %v, want %q", got, want)
	}
}

// TestRun_JSONFormat_ValidatesAgainstSchema asserts the status JSON
// envelope validates against schemas/status.v1.json. Populates a
// partial run directory so the report has non-empty steps, then runs
// the schema validator across the full output.
func TestRun_JSONFormat_ValidatesAgainstSchema(t *testing.T) {
	dir := t.TempDir()
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs:          []types.ACLRow{{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow}},
	}
	if err := rundir.WriteACLs(filepath.Join(dir, "acls.json"), set); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := status.Run(&buf, dir, status.FormatJSON); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := schema.ValidateStatusReport(buf.Bytes()); err != nil {
		t.Errorf("status JSON should validate against status.v1.json:\n%v\noutput:\n%s", err, buf.String())
	}
}

// TestRun_VerifyCounts asserts that status decodes verify.json as
// a `{results, counts}` envelope and surfaces
// EFFECTIVE_OK / missing / unknown counts in the text output
// (README-shaped). Three results with different statuses go in; three
// counts come out.
func TestRun_VerifyCounts(t *testing.T) {
	dir := t.TempDir()
	results := []verify.Result{
		{BindingID: "rb-1", Status: verify.StatusEffectiveOK},
		{BindingID: "rb-2", Status: verify.StatusEffectiveMissing, Detail: "no binding"},
		{BindingID: "rb-3", Status: verify.StatusEffectiveUnknown, Detail: "MDS unavailable"},
	}
	sum := verify.Summary{Results: results}
	sum.Counts = sum.AggregateCounts()
	data, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "verify.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := status.Run(&buf, dir, status.FormatText); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	want := "verify:            1 EFFECTIVE_OK, 1 missing, 1 unknown (3 total)"
	if !strings.Contains(out, want) {
		t.Errorf("output missing %q:\n%s", want, out)
	}

	// And the JSON shape exposes the same fields for CI consumers.
	buf.Reset()
	if err := status.Run(&buf, dir, status.FormatJSON); err != nil {
		t.Fatalf("run json: %v", err)
	}
	var rep struct {
		Verify struct {
			Present bool           `json:"present"`
			Detail  map[string]int `json:"detail"`
		} `json:"verify"`
	}
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Verify.Detail["total"] != 3 || rep.Verify.Detail["effective_ok"] != 1 ||
		rep.Verify.Detail["effective_missing"] != 1 || rep.Verify.Detail["effective_unknown"] != 1 {
		t.Errorf("unexpected verify counts in JSON: %+v", rep.Verify.Detail)
	}
}

// TestRun_VerifyCounts_BareArrayUnreadable asserts that bare-array-shaped
// verify.json (bare []Result) is surfaced as an "(unreadable)" detail
// rather than rendering fake-zero counts. Mirrors the behaviour
// delete-acls already enforces: an operator upgrading from bare-array sees
// a clear "re-run verify" message instead of a misleading partial
// render that then makes delete-acls reject the same file.
func TestRun_VerifyCounts_BareArrayUnreadable(t *testing.T) {
	dir := t.TempDir()
	results := []verify.Result{
		{BindingID: "rb-1", Status: verify.StatusEffectiveOK},
		{BindingID: "rb-2", Status: verify.StatusEffectiveMissing},
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "verify.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	// JSON output: Detail is the unreadable string, not a counts map.
	var buf bytes.Buffer
	if err := status.Run(&buf, dir, status.FormatJSON); err != nil {
		t.Fatalf("run: %v", err)
	}
	var rep struct {
		Verify struct {
			Present bool   `json:"present"`
			Detail  string `json:"detail"`
		} `json:"verify"`
	}
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rep.Verify.Present {
		t.Errorf("verify step should be present (file exists); got %+v", rep.Verify)
	}
	if !strings.Contains(rep.Verify.Detail, "unreadable") {
		t.Errorf("bare-array form should surface an unreadable detail; got %q", rep.Verify.Detail)
	}

	// Text output: the line should also flag the file as unreadable
	// rather than printing "0 EFFECTIVE_OK, 0 missing, ..." which would
	// mislead the operator into thinking verify succeeded.
	buf.Reset()
	if err := status.Run(&buf, dir, status.FormatText); err != nil {
		t.Fatalf("run text: %v", err)
	}
	if !strings.Contains(buf.String(), "unreadable") {
		t.Errorf("text output should flag bare-array verify.json as unreadable:\n%s", buf.String())
	}
}
