// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package csv_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	csvadapter "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/csv"
)

// genCSV writes a synthetic CSV with n rows and returns the path.
// Format matches the canonical IR header: id, principal, host,
// operation, resource_type, resource_name, pattern_type,
// permission_type.
func genCSV(b *testing.B, n int) string {
	b.Helper()

	var sb strings.Builder
	sb.WriteString("id,principal,host,operation,resource_type,resource_name,pattern_type,permission_type\n")
	for i := 1; i <= n; i++ {
		op := "Read"
		if i%2 == 0 {
			op = "Describe"
		}
		fmt.Fprintf(&sb,
			"%d,User:svc-%04d,*,%s,Topic,topic-%05d,LITERAL,Allow\n",
			i, i/4, op, i/2)
	}

	dir := b.TempDir()
	path := filepath.Join(dir, "bench.csv")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	return path
}

func BenchmarkExtract_1kRows(b *testing.B) {
	benchExtract(b, 1000)
}

// BenchmarkExtract_10kRows locks in the spec §12 scale target — CSV
// must parse 10k rows in well under a second. If this regresses past
// ~100ms on a typical dev box, look for an accidental O(n²) in the
// CSV path.
func BenchmarkExtract_10kRows(b *testing.B) {
	benchExtract(b, 10000)
}

func benchExtract(b *testing.B, n int) {
	b.Helper()
	path := genCSV(b, n)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a, err := csvadapter.New(path)
		if err != nil {
			b.Fatal(err)
		}
		set, _, _, _, err := a.Extract()
		if err != nil {
			b.Fatal(err)
		}
		if len(set.ACLs) != n {
			b.Fatalf("expected %d rows; got %d", n, len(set.ACLs))
		}
	}
}
