// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

//go:build linux

package cli_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// buildBinary compiles the CLI once per test run and returns the path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "monedula-acl-rbac")
	cmd := exec.Command("go", "build", "-o", bin, "../../../cmd/monedula-acl-rbac")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build binary: %v", err)
	}
	return bin
}

// fixture sets up a tmp run dir with a minimal plan.json that `apply`
// will inspect before prompting.
func fixture(t *testing.T) (planPath, tokenPath string) {
	t.Helper()
	tmp := t.TempDir()
	planPath = filepath.Join(tmp, "plan.json")
	body := `{"schema_version": "1","bindings":[],"unmapped":[],"rejected":[],"warnings":[],"deny_analysis":[]}`
	if err := os.WriteFile(planPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tokenPath = filepath.Join(tmp, "token")
	if err := os.WriteFile(tokenPath, []byte("fake-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return planPath, tokenPath
}

// TestPty_ApplyPromptShowsAndAcceptsYes verifies that running `apply`
// without --confirm and with stdin attached to a pty triggers the
// interactive prompt, and that typing "yes\n" gets past the prompt.
func TestPty_ApplyPromptShowsAndAcceptsYes(t *testing.T) {
	bin := buildBinary(t)
	planPath, tokenPath := fixture(t)

	cmd := exec.Command(bin,
		"apply",
		"--plan", planPath,
		"--mds-url", "http://127.0.0.1:1", // unreachable; the prompt fires first
		"--mds-token-file", tokenPath,
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start: %v", err)
	}
	defer ptmx.Close()

	// Read output until we see the prompt token.
	out := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 256)
		for {
			n, err := ptmx.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if strings.Contains(string(buf), "Type 'yes'") || strings.Contains(string(buf), "type 'yes'") {
					out <- string(buf)
					return
				}
			}
			if err == io.EOF {
				out <- string(buf)
				return
			}
			if err != nil {
				out <- string(buf) + " ERR: " + err.Error()
				return
			}
		}
	}()

	select {
	case got := <-out:
		if !strings.Contains(got, "yes") {
			t.Fatalf("never saw interactive prompt; got:\n%s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for interactive prompt")
	}

	if _, err := ptmx.Write([]byte("yes\n")); err != nil {
		t.Fatalf("write yes: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		// fine — exit code doesn't matter, just that it exited
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("binary did not exit after typing 'yes'")
	}
}

func TestPty_ApplyPromptRejectsNo(t *testing.T) {
	bin := buildBinary(t)
	planPath, tokenPath := fixture(t)

	cmd := exec.Command(bin,
		"apply",
		"--plan", planPath,
		"--mds-url", "http://127.0.0.1:1",
		"--mds-token-file", tokenPath,
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start: %v", err)
	}
	defer ptmx.Close()

	// Wait briefly for the prompt to render.
	time.Sleep(500 * time.Millisecond)

	if _, err := ptmx.Write([]byte("no\n")); err != nil {
		t.Fatalf("write no: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		// Expect non-zero exit code because "not confirmed".
		if err == nil {
			t.Errorf("expected non-zero exit when 'no' typed at prompt; got nil")
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 0 {
				t.Errorf("expected non-zero exit; got 0")
			}
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("binary did not exit after typing 'no'")
	}
}
