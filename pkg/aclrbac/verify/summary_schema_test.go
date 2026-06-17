// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package verify_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

// TestSummary_JSON_ValidatesAgainstSchema asserts that verify.Summary's
// JSON output conforms to schemas/verify-summary.v1.json. Locks the
// envelope shape against drift; downstream CI consumers validate
// against the same schema.
func TestSummary_JSON_ValidatesAgainstSchema(t *testing.T) {
	s := verify.Summary{
		PlanSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Results: []verify.Result{
			{BindingID: "rb-0123456789ab", SourceACLID: 1, Status: verify.StatusEffectiveOK},
			{BindingID: "rb-cdef01234567", SourceACLID: 2, Status: verify.StatusEffectiveMissing, Detail: "no binding"},
			{SourceACLID: 3, Status: verify.StatusEffectiveUnknown, Detail: "MDS unavailable"},
		},
	}
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateVerifySummary(buf.Bytes()); err != nil {
		t.Errorf("verify summary failed schema validation: %v\noutput:\n%s", err, buf.String())
	}
	var raw struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.SchemaVersion != "1" {
		t.Errorf("schema_version: got %q want %q", raw.SchemaVersion, "1")
	}
}

// TestSummary_BindingsExistMode_ValidatesAgainstSchema asserts the
// bindings-exist mode envelope (BINDING_EXISTS / BINDING_MISSING
// statuses, the mode field, and binding_* counts) validates and that
// AggregateCounts populates the new binding counts.
func TestSummary_BindingsExistMode_ValidatesAgainstSchema(t *testing.T) {
	s := verify.Summary{
		PlanSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Mode:       "bindings-exist",
		Results: []verify.Result{
			{BindingID: "rb-0123456789ab", Status: verify.StatusBindingExists},
			{BindingID: "rb-cdef01234567", Status: verify.StatusBindingMissing},
		},
	}
	// AggregateCounts must populate binding_exists / binding_missing.
	c := s.AggregateCounts()
	if c.BindingExists != 1 || c.BindingMissing != 1 {
		t.Errorf("counts: got exists=%d missing=%d, want 1/1", c.BindingExists, c.BindingMissing)
	}

	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateVerifySummary(buf.Bytes()); err != nil {
		t.Errorf("bindings-exist summary failed schema validation: %v\noutput:\n%s", err, buf.String())
	}
	var raw struct {
		Mode   string `json:"mode"`
		Counts struct {
			BindingExists  int `json:"binding_exists"`
			BindingMissing int `json:"binding_missing"`
		} `json:"counts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Mode != "bindings-exist" {
		t.Errorf("mode: got %q want %q", raw.Mode, "bindings-exist")
	}
	if raw.Counts.BindingExists != 1 || raw.Counts.BindingMissing != 1 {
		t.Errorf("envelope counts: got exists=%d missing=%d, want 1/1", raw.Counts.BindingExists, raw.Counts.BindingMissing)
	}
}
