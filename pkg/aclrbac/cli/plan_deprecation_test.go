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

// captureStderr runs fn with os.Stderr redirected and returns what was
// written. Restores os.Stderr on exit.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stderr = old
	return <-done
}

func TestPlan_AllowDenyDropAlias_PrintsDeprecation(t *testing.T) {
	tmp := t.TempDir()
	aclsPath := filepath.Join(tmp, "acls.json")
	scopesPath := filepath.Join(tmp, "scopes.yaml")
	planPath := filepath.Join(tmp, "plan.json")
	if err := os.WriteFile(aclsPath, []byte(`{"schema_version": "1","source":{"type":"json","generated_at":"2026-01-01T00:00:00Z"},"acls":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scopesPath, []byte("kafka_cluster: lkc-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() {
		_ = cli.Execute([]string{
			"plan", "--acls", aclsPath, "--scopes", scopesPath, "--out", planPath,
			"--allow-deny-drop",
		})
	})
	if !strings.Contains(strings.ToLower(out), "deprecat") {
		t.Errorf("expected deprecation warning when --allow-deny-drop is used; got:\n%s", out)
	}
}
