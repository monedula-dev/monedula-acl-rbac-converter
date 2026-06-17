// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
)

func TestResolve_ExplicitRunDirWins(t *testing.T) {
	t.Setenv("MONEDULA_ACL_RBAC_RUN_DIR", "/from/env")
	tmp := t.TempDir()
	got, err := rundir.Resolve(rundir.ResolveOptions{
		ExplicitRunDir: tmp,
		Out:            "/from/out/file.json",
		InputArtifact:  "/from/input/plan.json",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != tmp {
		t.Errorf("got %q, want %q (explicit wins)", got, tmp)
	}
}

// TestResolve_AutoNameDisambiguatesCollision pins that two auto-resolved run
// dirs at the same timestamp do not collide: once the timestamped dir exists,
// the next resolution gets a -N suffix instead of sharing (and overwriting)
// it.
func TestResolve_AutoNameDisambiguatesCollision(t *testing.T) {
	tmp := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return fixed }

	first, err := rundir.Resolve(rundir.ResolveOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := rundir.Ensure(first); err != nil {
		t.Fatal(err)
	}
	second, err := rundir.Resolve(rundir.ResolveOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Errorf("same-second auto run dirs must not collide; both resolved to %q", first)
	}
}

func TestResolve_OutParentSecond(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "plan.json")
	got, err := rundir.Resolve(rundir.ResolveOptions{
		Out:           out,
		InputArtifact: "/from/input/plan.json",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != tmp {
		t.Errorf("got %q, want %q (out parent)", got, tmp)
	}
}

func TestResolve_InputArtifactThird(t *testing.T) {
	tmp := t.TempDir()
	plan := filepath.Join(tmp, "plan.json")
	if err := os.WriteFile(plan, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := rundir.Resolve(rundir.ResolveOptions{
		InputArtifact: plan,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != tmp {
		t.Errorf("got %q, want %q (input parent)", got, tmp)
	}
}

func TestResolve_EnvFourth(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("MONEDULA_ACL_RBAC_RUN_DIR", tmp)
	got, err := rundir.Resolve(rundir.ResolveOptions{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != tmp {
		t.Errorf("got %q, want %q (env)", got, tmp)
	}
}

func TestResolve_AutoTimestampLast(t *testing.T) {
	t.Setenv("MONEDULA_ACL_RBAC_RUN_DIR", "")
	tmp := t.TempDir()
	t.Chdir(tmp)

	got, err := rundir.Resolve(rundir.ResolveOptions{Now: func() time.Time {
		return time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := filepath.Join(tmp, "runs", "2026-05-21T10-00-00Z")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEnsure_CreatesDir(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "billing-batch-1")
	if err := rundir.Ensure(target); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("not a dir")
	}
}

func TestTimestamp_FormatStable(t *testing.T) {
	got := rundir.Timestamp(time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC))
	if !strings.HasSuffix(got, "Z") {
		t.Errorf("must end in Z; got %q", got)
	}
	if strings.Contains(got, ":") {
		t.Errorf("must not contain colons (path-unsafe on Windows); got %q", got)
	}
}
