// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package diff_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/diff"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestACLs_AddedAndRemoved(t *testing.T) {
	a := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}
	b := []types.ACLRow{
		{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "shipments", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}

	var buf bytes.Buffer
	if err := diff.ACLs(&buf, a, b, diff.FormatText); err != nil {
		t.Fatalf("diff: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "REMOVED") {
		t.Errorf("expected REMOVED for orders:\n%s", out)
	}
	if !strings.Contains(out, "ADDED") {
		t.Errorf("expected ADDED for shipments:\n%s", out)
	}
}

func TestPlans_BindingsDiff(t *testing.T) {
	a := types.Plan{Bindings: []types.Binding{{ID: "rb-aaaaaaaaaaaa", Principal: "User:alice", Role: "DeveloperRead"}}}
	b := types.Plan{Bindings: []types.Binding{{ID: "rb-bbbbbbbbbbbb", Principal: "User:bob", Role: "DeveloperRead"}}}

	var buf bytes.Buffer
	if err := diff.Plans(&buf, a, b, diff.FormatText); err != nil {
		t.Fatalf("diff: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "rb-aaaaaaaaaaaa") || !strings.Contains(out, "rb-bbbbbbbbbbbb") {
		t.Errorf("expected both binding IDs in diff:\n%s", out)
	}
}

// TestACLs_JSONFormat_HasSchemaVersionEnvelope asserts the diff JSON
// output is wrapped in a {schema_version, added, removed} envelope
// (parity with apply/verify/status/report --format json). CI consumers
// reading the envelope can fail-fast if schema_version changes.
func TestACLs_JSONFormat_HasSchemaVersionEnvelope(t *testing.T) {
	a := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}
	b := []types.ACLRow{
		{ID: 2, Principal: "User:bob", Host: "*", Operation: types.OpWrite, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}

	var buf bytes.Buffer
	if err := diff.ACLs(&buf, a, b, diff.FormatJSON); err != nil {
		t.Fatalf("diff: %v", err)
	}
	var got diff.ACLDiff
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if got.SchemaVersion != "1" {
		t.Errorf("schema_version: got %q, want %q", got.SchemaVersion, "1")
	}
	if len(got.Added) != 1 || got.Added[0].Principal != "User:bob" {
		t.Errorf("added: got %+v", got.Added)
	}
	if len(got.Removed) != 1 || got.Removed[0].Principal != "User:alice" {
		t.Errorf("removed: got %+v", got.Removed)
	}
}

// TestACLs_JSONFormat_EmptyDiff asserts the envelope still surfaces
// schema_version and empty arrays (not null) when both inputs are
// identical. Lets downstream consumers iterate unconditionally.
func TestACLs_JSONFormat_EmptyDiff(t *testing.T) {
	a := []types.ACLRow{
		{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
	}

	var buf bytes.Buffer
	if err := diff.ACLs(&buf, a, a, diff.FormatJSON); err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !strings.Contains(buf.String(), `"schema_version":"1"`) {
		t.Errorf("expected schema_version in empty-diff envelope:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"added":[]`) || !strings.Contains(buf.String(), `"removed":[]`) {
		t.Errorf("empty arrays should marshal as [] not null:\n%s", buf.String())
	}
}

// TestPlans_ScopeChangeDetectedAsChanged is the regression guard for the
// "diff missed Scope changes" defect (D1): the earlier comparator only
// checked Action + Role, so two bindings with the same ID but a different
// `Scope.KafkaCluster` (e.g. an operator hand-edited plan.json + ran
// `plan --revalidate`) were classified as unchanged — silent drift before
// apply. The comparator now uses reflect.DeepEqual.
func TestPlans_ScopeChangeDetectedAsChanged(t *testing.T) {
	a := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate, Principal: "User:alice",
			Role: "DeveloperRead", Scope: types.Scope{KafkaCluster: "lkc-prod"}},
	}}
	b := types.Plan{Bindings: []types.Binding{
		// Same ID, same Action+Role, but different KafkaCluster.
		{ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate, Principal: "User:alice",
			Role: "DeveloperRead", Scope: types.Scope{KafkaCluster: "lkc-staging"}},
	}}
	var buf bytes.Buffer
	if err := diff.Plans(&buf, a, b, diff.FormatJSON); err != nil {
		t.Fatalf("diff: %v", err)
	}
	var got diff.PlanDiff
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if len(got.Changed) != 1 {
		t.Fatalf("expected 1 changed binding (Scope.KafkaCluster diff); got %d:\nadded=%+v removed=%+v changed=%+v",
			len(got.Changed), got.Added, got.Removed, got.Changed)
	}
	if got.Changed[0].Scope.KafkaCluster != "lkc-staging" {
		t.Errorf("changed entry should reflect the NEW scope; got %+v", got.Changed[0])
	}
}

// TestPlans_ResourcePatternChangeDetectedAsChanged is the same regression
// guard for a different binding field the old comparator missed.
func TestPlans_ResourcePatternChangeDetectedAsChanged(t *testing.T) {
	a := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate, Principal: "User:alice", Role: "DeveloperRead",
			ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral}}},
	}}
	b := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate, Principal: "User:alice", Role: "DeveloperRead",
			ResourcePatterns: []types.ResourcePattern{{ResourceType: types.ResourceTopic, Name: "events", PatternType: types.PatternLiteral}}},
	}}
	var buf bytes.Buffer
	if err := diff.Plans(&buf, a, b, diff.FormatJSON); err != nil {
		t.Fatalf("diff: %v", err)
	}
	var got diff.PlanDiff
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if len(got.Changed) != 1 {
		t.Fatalf("expected 1 changed binding (ResourcePattern.Name diff); got %d", len(got.Changed))
	}
}

// TestPlans_JSONFormat_HasSchemaVersionEnvelope mirrors the ACLs test
// for plan-level diffs: {schema_version, added, removed, changed}.
func TestPlans_JSONFormat_HasSchemaVersionEnvelope(t *testing.T) {
	a := types.Plan{Bindings: []types.Binding{
		{ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate, Principal: "User:alice", Role: "DeveloperRead"},
	}}
	b := types.Plan{Bindings: []types.Binding{
		{ID: "rb-bbbbbbbbbbbb", Action: types.ActionCreate, Principal: "User:bob", Role: "DeveloperRead"},
	}}

	var buf bytes.Buffer
	if err := diff.Plans(&buf, a, b, diff.FormatJSON); err != nil {
		t.Fatalf("diff: %v", err)
	}
	var got diff.PlanDiff
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if got.SchemaVersion != "1" {
		t.Errorf("schema_version: got %q, want %q", got.SchemaVersion, "1")
	}
	if len(got.Added) != 1 || got.Added[0].ID != "rb-bbbbbbbbbbbb" {
		t.Errorf("added: got %+v", got.Added)
	}
	if len(got.Removed) != 1 || got.Removed[0].ID != "rb-aaaaaaaaaaaa" {
		t.Errorf("removed: got %+v", got.Removed)
	}
	if got.Changed == nil {
		t.Errorf("changed should be [] not null; got nil")
	}
}
