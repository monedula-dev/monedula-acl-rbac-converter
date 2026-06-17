// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

// ---- status command tests ---------------------------------------------------

// TestStatus_HappyPath: status on a populated run directory exits 0 and
// produces output mentioning the directory.
func TestStatus_HappyPath(t *testing.T) {
	dir, planPath := buildPlan(t)
	_ = planPath

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w

	exit := cli.Execute([]string{"status", dir})
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if exit != 0 {
		t.Fatalf("status exit %d; output:\n%s", exit, buf.String())
	}
	if !strings.Contains(buf.String(), dir) {
		t.Errorf("expected run directory path in status output; got:\n%s", buf.String())
	}
}

// TestStatus_EmptyDir: status on an empty tmp dir should still exit 0 (all
// steps NOT RUN) and not crash.
func TestStatus_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	exit := cli.Execute([]string{"status", dir})
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if exit != 0 {
		t.Fatalf("status on empty dir exit %d", exit)
	}
	if !strings.Contains(buf.String(), "NOT RUN") {
		t.Errorf("expected 'NOT RUN' in status output for empty dir; got:\n%s", buf.String())
	}
}

// TestStatus_MissingArgument: status without arguments should exit non-zero.
func TestStatus_MissingArgument(t *testing.T) {
	exit := cli.Execute([]string{"status"})
	if exit == 0 {
		t.Error("expected non-zero exit when no run dir argument provided")
	}
}

// ---- diff command tests -----------------------------------------------------

// TestDiff_ACLs_TextFormat: diff --acls A B outputs added/removed lines or
// nothing when identical.
func TestDiff_ACLs_TextFormat(t *testing.T) {
	tmp := t.TempDir()
	aclsA := filepath.Join(tmp, "acls-a.json")
	aclsB := filepath.Join(tmp, "acls-b.json")

	// A has alice:Read, B adds bob:Write and removes alice.
	const aA = `{"schema_version": "1","source":{"type":"json","generated_at":"2026-01-01T00:00:00Z"},"acls":[
		{"id":1,"principal":"User:alice","host":"*","operation":"Read","resource_type":"Topic","resource_name":"orders","pattern_type":"LITERAL","permission_type":"Allow"}
	]}`
	const aB = `{"schema_version": "1","source":{"type":"json","generated_at":"2026-01-01T00:00:00Z"},"acls":[
		{"id":2,"principal":"User:bob","host":"*","operation":"Write","resource_type":"Topic","resource_name":"orders","pattern_type":"LITERAL","permission_type":"Allow"}
	]}`
	if err := os.WriteFile(aclsA, []byte(aA), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclsB, []byte(aB), 0o644); err != nil {
		t.Fatal(err)
	}

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	exit := cli.Execute([]string{"diff", "--acls", aclsA + "," + aclsB})
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if exit != 0 {
		t.Fatalf("diff --acls exit %d; output:\n%s", exit, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "bob") {
		t.Errorf("expected bob to appear in diff output; got:\n%s", out)
	}
}

// TestDiff_Plans_TextFormat: diff --plan A B compares two identical plan.json
// files and returns exit 0 (no diff = empty output).
func TestDiff_Plans_TextFormat(t *testing.T) {
	_, planPath := buildPlan(t)

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	// Pass the same plan twice — diff should show no changes.
	exit := cli.Execute([]string{"diff", "--plan", planPath + "," + planPath})
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if exit != 0 {
		t.Fatalf("diff --plan exit %d; output:\n%s", exit, buf.String())
	}
}

// TestDiff_NoFlagsGivesUsageError: diff without --acls or --plan should exit
// non-zero with exit code 1 (usage).
func TestDiff_NoFlagsGivesUsageError(t *testing.T) {
	exit := cli.Execute([]string{"diff"})
	if exit == 0 {
		t.Error("expected non-zero exit when neither --acls nor --plan provided")
	}
}
