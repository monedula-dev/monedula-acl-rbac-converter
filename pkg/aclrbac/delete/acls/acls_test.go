// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package acls_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/acls"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

func samplePlan() types.Plan {
	return types.Plan{
		SchemaVersion: "1",
		GeneratedAt:   "2026-05-21T10:05:00Z",
		Bindings: []types.Binding{{
			ID: "rb-aaaaaaaaaaaa", Action: types.ActionCreate,
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

func TestGenerate_WritesScriptAndRollback(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	aclSet := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		},
	}
	aclsPath := filepath.Join(dir, "acls.json")
	if err := rundir.WriteACLs(aclsPath, aclSet); err != nil {
		t.Fatalf("write acls: %v", err)
	}

	verifyRes := []verify.Result{{BindingID: "rb-aaaaaaaaaaaa", Status: verify.StatusEffectiveOK}}

	err := acls.Generate(acls.Options{
		RunDir:           dir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           verifyRes,
		Principals:       []string{"User:alice"},
		BootstrapServers: "kafka.example.com:9093",
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "delete-acls.sh"))
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	if !strings.HasPrefix(string(body), "#!/usr/bin/env bash\nset -euo pipefail") {
		t.Errorf("script must start with shebang+strict-mode:\n%s", body[:100])
	}
	// Every argv element except the binary is shell.Quote'd now (including
	// flag names) — see writeRemove. A value starting with "--" can't escape
	// quoting any more (TestGoldenDeleteACLsScript/dash_dash_value_is_quoted
	// is the dedicated regression guard).
	for _, want := range []string{
		"kafka-acls",
		"'--remove'",
		"'--allow-principal' 'User:alice'",
		"'--topic' 'orders'",
		"'--operation' 'Read'",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("script missing %q", want)
		}
	}

	rollback, err := os.ReadFile(filepath.Join(dir, "rollback.sh"))
	if err != nil {
		t.Fatalf("read rollback: %v", err)
	}
	if !strings.Contains(string(rollback), "--add") {
		t.Errorf("rollback should use --add:\n%s", rollback)
	}

	deleted, err := os.ReadFile(filepath.Join(dir, "deleted-acls.json"))
	if err != nil {
		t.Fatalf("read deleted-acls.json: %v", err)
	}
	if !strings.Contains(string(deleted), "orders") {
		t.Errorf("deleted-acls.json missing topic:\n%s", deleted)
	}
}

// TestGenerate_RejectsMissingBootstrapServer asserts that delete-acls
// refuses to write a script with no bootstrap server (parity with
// delete-deny-acls). The generated `kafka-acls --remove` invocations need
// one; previously the failure surfaced only at `bash delete-acls.sh` time
// as `--bootstrap-server ""`, long after the run-directory artefacts were
// committed. No artefacts must be written on validation failure.
func TestGenerate_RejectsMissingBootstrapServer(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}
	aclsPath := filepath.Join(dir, "acls.json")
	if err := rundir.WriteACLs(aclsPath, types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		},
	}); err != nil {
		t.Fatalf("write acls: %v", err)
	}
	verifyRes := []verify.Result{{BindingID: "rb-aaaaaaaaaaaa", Status: verify.StatusEffectiveOK}}

	for _, bs := range []string{"", "   "} {
		err := acls.Generate(acls.Options{
			RunDir:     dir,
			PlanPath:   planPath,
			ACLsPath:   aclsPath,
			Verify:     verifyRes,
			Principals: []string{"User:alice"},
			// BootstrapServers blank/whitespace-only
			BootstrapServers: bs,
		})
		if err == nil {
			t.Fatalf("expected error for bootstrap-server %q", bs)
		}
		if !strings.Contains(err.Error(), "--bootstrap-server") {
			t.Errorf("error should name --bootstrap-server; got: %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "delete-acls.sh")); statErr == nil {
			t.Error("script should not be written when validation fails")
		}
	}
}

// TestGenerate_CreatesMissingRunDir confirms Generate calls rundir.Ensure
// up-front (parity with plan / extract). Before this guard, a typo in
// --run-dir surfaced as a confusing "open .../deleted-acls.json: no such
// file or directory" mid-way through artefact emission.
func TestGenerate_CreatesMissingRunDir(t *testing.T) {
	parent := t.TempDir()
	planPath := filepath.Join(parent, "plan.json")
	if err := rundir.WritePlan(planPath, samplePlan()); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := rundir.WriteChecksum(planPath); err != nil {
		t.Fatalf("checksum: %v", err)
	}
	aclsPath := filepath.Join(parent, "acls.json")
	if err := rundir.WriteACLs(aclsPath, types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "json", GeneratedAt: "2026-05-21T10:00:00Z"},
		ACLs: []types.ACLRow{
			{ID: 1, Principal: "User:alice", Host: "*", Operation: types.OpRead, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
			{ID: 2, Principal: "User:alice", Host: "*", Operation: types.OpDescribe, ResourceType: types.ResourceTopic, ResourceName: "orders", PatternType: types.PatternLiteral, PermissionType: types.PermissionAllow},
		},
	}); err != nil {
		t.Fatalf("write acls: %v", err)
	}

	// RunDir is a sub-path that does not yet exist.
	runDir := filepath.Join(parent, "future-run-dir")
	verifyRes := []verify.Result{{BindingID: "rb-aaaaaaaaaaaa", Status: verify.StatusEffectiveOK}}

	if err := acls.Generate(acls.Options{
		RunDir:           runDir,
		PlanPath:         planPath,
		ACLsPath:         aclsPath,
		Verify:           verifyRes,
		Principals:       []string{"User:alice"},
		BootstrapServers: "kafka.example.com:9093",
	}); err != nil {
		t.Fatalf("Generate must create the run dir: %v", err)
	}

	// All three core artefacts must land in the freshly created dir.
	for _, name := range []string{"delete-acls.sh", "rollback.sh", "deleted-acls.json"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Errorf("expected %s in newly-created run dir: %v", name, err)
		}
	}
}
