// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package csv_test

import (
	"os"
	"path/filepath"
	"testing"

	csvadapter "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/csv"
)

func TestExtract_CSV(t *testing.T) {
	a, err := csvadapter.New("testdata/basic.csv")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 2 {
		t.Errorf("got %d ACLs, want 2", len(set.ACLs))
	}
	if set.ACLs[0].Principal != "User:alice" {
		t.Errorf("principal: got %q", set.ACLs[0].Principal)
	}
}

func TestExtract_CSV_MissingColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(path, []byte("id,host,operation,resource_type,resource_name,pattern_type,permission_type\n1,*,Read,Topic,orders,LITERAL,Allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := csvadapter.New(path)
	if _, _, _, _, err := a.Extract(); err == nil {
		t.Fatal("expected error for missing column")
	}
}

// FuzzCSV asserts that csv.Adapter.Extract never panics on arbitrary
// byte input. Run with:
//
//	go test ./pkg/aclrbac/extract/csv/ -fuzz=FuzzCSV -fuzztime=30s
func FuzzCSV(f *testing.F) {
	f.Add([]byte("id,principal,host,operation,resource_type,resource_name,pattern_type,permission_type\n1,User:a,*,Read,Topic,t1,LITERAL,Allow\n"))
	f.Add([]byte(""))
	f.Add([]byte("not,a,proper,csv\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "input.csv")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		a, err := csvadapter.New(path)
		if err != nil {
			return
		}
		_, _, _, _, _ = a.Extract()
	})
}
