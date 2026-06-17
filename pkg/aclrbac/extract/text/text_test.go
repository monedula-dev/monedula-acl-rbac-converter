// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package text_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/text"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestExtract_Basic(t *testing.T) {
	a, err := text.New("testdata/basic.txt")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(set.ACLs) != 3 {
		t.Errorf("got %d ACLs, want 3", len(set.ACLs))
	}
	if set.ACLs[0].ID != 1 || set.ACLs[2].ID != 3 {
		t.Errorf("ids: %v %v %v", set.ACLs[0].ID, set.ACLs[1].ID, set.ACLs[2].ID)
	}
	if set.ACLs[0].Operation != types.OpRead {
		t.Errorf("op: got %q, want Read", set.ACLs[0].Operation)
	}
}

func TestExtract_HostNonWildcardPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "h.txt")
	body := "Current ACLs for resource `ResourcePattern(resourceType=TOPIC, name=orders, patternType=LITERAL)`:\n" +
		"\t(principal=User:alice, host=10.0.0.5, operation=READ, permissionType=ALLOW)\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := text.New(path)
	set, _, _, _, err := a.Extract()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.ACLs) != 1 {
		t.Fatalf("got %d ACLs", len(set.ACLs))
	}
	if set.ACLs[0].Host != "10.0.0.5" {
		t.Errorf("host should be carried verbatim: got %q", set.ACLs[0].Host)
	}
}

// FuzzText asserts that text.Adapter.Extract never panics on arbitrary
// byte input. Run with:
//
//	go test ./pkg/aclrbac/extract/text/ -fuzz=FuzzText -fuzztime=30s
func FuzzText(f *testing.F) {
	f.Add([]byte("Current ACLs for resource `ResourcePattern(resourceType=TOPIC, name=t1, patternType=LITERAL)`:\n\t(principal=User:a, host=*, operation=READ, permissionType=ALLOW)\n"))
	f.Add([]byte(""))
	f.Add([]byte("garbage with no acl lines\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "input.txt")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		a, err := text.New(path)
		if err != nil {
			return
		}
		// Invariant: parse never panics. Errors are acceptable.
		_, _, _, _, _ = a.Extract()
	})
}
