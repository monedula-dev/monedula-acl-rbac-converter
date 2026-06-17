// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
)

func TestChecksumWriteAndVerify_OK(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan, []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := rundir.WriteChecksum(plan); err != nil {
		t.Fatalf("write checksum: %v", err)
	}

	if err := rundir.VerifyChecksum(plan); err != nil {
		t.Errorf("verify after write should succeed; got %v", err)
	}
}

func TestChecksum_FailsAfterModification(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan, []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := rundir.WriteChecksum(plan); err != nil {
		t.Fatalf("write checksum: %v", err)
	}

	// Modify the plan after checksum.
	if err := os.WriteFile(plan, []byte(`{"hello":"modified"}`), 0o644); err != nil {
		t.Fatalf("modify: %v", err)
	}

	if err := rundir.VerifyChecksum(plan); err == nil {
		t.Errorf("verify should fail for modified plan")
	}
}

func TestChecksum_MissingChecksumFile(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := rundir.VerifyChecksum(plan); err == nil {
		t.Errorf("verify should fail when .sha256 is missing")
	}
}
