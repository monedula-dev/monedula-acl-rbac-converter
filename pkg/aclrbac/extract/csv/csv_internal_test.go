// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package csv

import (
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
)

// TestParseCSV_QuotedFieldWithHashLineNotStripped pins that a '#'-leading line
// INSIDE a quoted multiline field is not treated as a comment. The old
// stripComments split on raw newlines and deleted any '#'-leading physical
// line before CSV parsing, corrupting RFC 4180 quoted multiline records (here
// it would leave an unterminated quote and fail the parse).
func TestParseCSV_QuotedFieldWithHashLineNotStripped(t *testing.T) {
	data := []byte("# header comment\n" +
		"id,principal,host,operation,resource_type,resource_name,pattern_type,permission_type\n" +
		"1,User:alice,*,Read,Topic,\"orders\n#still-part-of-name\",LITERAL,Allow\n")
	rows, err := parseCSV(data, extract.NewLogger())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	want := "orders\n#still-part-of-name"
	if rows[0].ResourceName != want {
		t.Errorf("resource_name: got %q, want %q (the '#' line must stay inside the quoted field)", rows[0].ResourceName, want)
	}
}

// TestParseCSV_IndentedCommentStillStripped keeps the existing convenience: a
// full-line comment (even indented) outside any quoted field is dropped.
func TestParseCSV_IndentedCommentStillStripped(t *testing.T) {
	data := []byte("id,principal,host,operation,resource_type,resource_name,pattern_type,permission_type\n" +
		"   # an indented comment line\n" +
		"1,User:alice,*,Read,Topic,orders,LITERAL,Allow\n")
	rows, err := parseCSV(data, extract.NewLogger())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (indented comment must be stripped)", len(rows))
	}
}
