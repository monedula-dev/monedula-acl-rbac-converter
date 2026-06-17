// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Command sync-schemas copies the canonical JSON schemas at repo root
// into pkg/aclrbac/schema/, where //go:embed picks them up.
//
// Runs identically on Linux, macOS, and Windows — no cp/copy/robocopy
// surface needed in the Makefile.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	pairs := [][2]string{
		{"schemas/acls.v1.json", "pkg/aclrbac/schema/acls.v1.json"},
		{"schemas/plan.v1.json", "pkg/aclrbac/schema/plan.v1.json"},
		{"schemas/apply-summary.v1.json", "pkg/aclrbac/schema/apply-summary.v1.json"},
		{"schemas/verify-summary.v1.json", "pkg/aclrbac/schema/verify-summary.v1.json"},
		{"schemas/status.v1.json", "pkg/aclrbac/schema/status.v1.json"},
		{"schemas/report.v1.json", "pkg/aclrbac/schema/report.v1.json"},
	}
	for _, p := range pairs {
		if err := copyFile(p[0], p[1]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("synced", p[0], "->", p[1])
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy: %w", err)
	}
	// Surface a flush-on-close failure (ENOSPC, AV interference, network FS)
	// rather than printing "synced" while the schema file is truncated.
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}
