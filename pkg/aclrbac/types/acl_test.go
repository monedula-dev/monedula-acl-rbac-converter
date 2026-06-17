// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types_test

import (
	"encoding/json"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestACLRowRoundTrip(t *testing.T) {
	row := types.ACLRow{
		ID:             1,
		Principal:      "User:alice",
		Host:           "*",
		Operation:      types.OpRead,
		ResourceType:   types.ResourceTopic,
		ResourceName:   "orders",
		PatternType:    types.PatternLiteral,
		PermissionType: types.PermissionAllow,
	}

	data, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.ACLRow
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got != row {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, row)
	}
}

func TestACLSetSchemaVersion(t *testing.T) {
	set := types.ACLSet{
		SchemaVersion: "1",
		Source: types.ACLSetSource{
			Type:        "json",
			GeneratedAt: "2026-05-21T10:00:00Z",
		},
		ACLs: []types.ACLRow{},
	}

	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := `{"schema_version":"1","source":{"type":"json","generated_at":"2026-05-21T10:00:00Z"},"acls":[]}`
	if string(data) != want {
		t.Errorf("unexpected JSON:\n got %s\nwant %s", data, want)
	}
}
