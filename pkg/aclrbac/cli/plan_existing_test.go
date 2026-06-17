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
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// TestPlan_ExistingBindingsBecomeSkipExists writes a hand-crafted
// acls.json + existing-bindings.json sidecar in the same dir, runs the
// real CLI's `plan` command, and asserts the binding that matches the
// existing record gets Action=SKIP_EXISTS instead of CREATE. This is the
// end-to-end proof that the CFK/K8s → sidecar → planner loop works.
//
// We don't drive the test through `extract --from cfk` because the CFK
// extractor only emits ALL-on-Cluster ACLs from the Kafka CR's
// superUsers; it doesn't synthesize topic ACLs that would match a
// ConfluentRolebinding. Hand-crafting both files focuses the test on
// the plan→sidecar interaction, which is what this milestone added.
func TestPlan_ExistingBindingsBecomeSkipExists(t *testing.T) {
	tmp := t.TempDir()
	rundir := filepath.Join(tmp, "run")
	if err := os.MkdirAll(rundir, 0o755); err != nil {
		t.Fatal(err)
	}
	aclsPath := filepath.Join(rundir, "acls.json")
	scopesPath := filepath.Join(rundir, "scopes.yaml")
	planPath := filepath.Join(rundir, "plan.json")
	existingPath := filepath.Join(rundir, "existing-bindings.json")

	// Read + Describe on topic "orders" for User:alice → planner will
	// build a DeveloperRead binding.
	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-existing binding for the same (principal, role, scope, pattern)
	// the planner is about to produce. classifyAgainstExisting will match
	// and switch Action to SKIP_EXISTS.
	existing := []types.Binding{
		{
			Action:    types.ActionCreate,
			Principal: "User:alice",
			Role:      "DeveloperRead",
			Scope:     types.Scope{KafkaCluster: "lkc-kafka01"},
			ResourcePatterns: []types.ResourcePattern{
				{ResourceType: types.ResourceTopic, Name: "orders", PatternType: types.PatternLiteral},
			},
		},
	}
	existingData, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.WriteFile(existingPath, existingData, 0o644); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	})
	if exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	planData, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read plan.json: %v", err)
	}
	if !strings.Contains(string(planData), `"action": "SKIP_EXISTS"`) {
		t.Errorf("expected SKIP_EXISTS in plan.json; got:\n%s", planData)
	}
	if strings.Contains(string(planData), `"action": "CREATE"`) {
		t.Errorf("plan should have no CREATE bindings (alice's matched existing); got:\n%s", planData)
	}
}

// TestPlan_NoSidecarLeavesActionCreate confirms the negative path: when
// existing-bindings.json is absent, the same ACLs produce a CREATE
// binding. Guards against accidentally always-marking-as-SKIP_EXISTS.
func TestPlan_NoSidecarLeavesActionCreate(t *testing.T) {
	tmp := t.TempDir()
	rundir := filepath.Join(tmp, "run")
	if err := os.MkdirAll(rundir, 0o755); err != nil {
		t.Fatal(err)
	}
	aclsPath := filepath.Join(rundir, "acls.json")
	scopesPath := filepath.Join(rundir, "scopes.yaml")
	planPath := filepath.Join(rundir, "plan.json")

	const aclsJSON = `{
  "schema_version": "1",
  "source": {"type": "json", "generated_at": "2026-05-24T00:00:00Z"},
  "acls": [
    {"id": 1, "principal": "User:alice", "host": "*", "operation": "Read",     "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"},
    {"id": 2, "principal": "User:alice", "host": "*", "operation": "Describe", "resource_type": "Topic", "resource_name": "orders", "pattern_type": "LITERAL", "permission_type": "Allow"}
  ]
}`
	if err := os.WriteFile(aclsPath, []byte(aclsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-kafka01\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{
		"plan",
		"--acls", aclsPath,
		"--scopes", scopesPath,
		"--out", planPath,
	})
	if exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}

	planData, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read plan.json: %v", err)
	}
	if !strings.Contains(string(planData), `"action": "CREATE"`) {
		t.Errorf("expected CREATE action without sidecar; got:\n%s", planData)
	}
	if strings.Contains(string(planData), `"action": "SKIP_EXISTS"`) {
		t.Errorf("plan should have no SKIP_EXISTS bindings without sidecar; got:\n%s", planData)
	}
}
