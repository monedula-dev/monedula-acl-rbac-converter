// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

func TestPlan_AlwaysWritesReportTxt(t *testing.T) {
	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	reportPath := filepath.Join(tmp, "report.txt")

	if err := os.WriteFile(aclsPath, []byte(`{"schema_version": "1","source":{"type":"json","generated_at":"2026-01-01T00:00:00Z"},"acls":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := cli.Execute([]string{"plan", "--acls", aclsPath, "--scopes", scopesPath, "--out", planPath})
	if exit != 0 {
		t.Fatalf("plan exit %d", exit)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("report.txt should be co-emitted; %v", err)
	}
}
