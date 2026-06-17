// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package schema_test

import (
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
)

func TestValidateACLs_Valid(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"source": { "type": "json", "generated_at": "2026-05-21T10:00:00Z" },
		"acls": [{
			"id": 1, "principal": "User:alice", "host": "*",
			"operation": "Read", "resource_type": "Topic",
			"resource_name": "orders", "pattern_type": "LITERAL",
			"permission_type": "Allow"
		}]
	}`)
	if err := schema.ValidateACLs(doc); err != nil {
		t.Fatalf("expected valid; got: %v", err)
	}
}

func TestValidateACLs_InvalidOperation(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"source": { "type": "json", "generated_at": "2026-05-21T10:00:00Z" },
		"acls": [{
			"id": 1, "principal": "User:alice", "host": "*",
			"operation": "Bogus", "resource_type": "Topic",
			"resource_name": "orders", "pattern_type": "LITERAL",
			"permission_type": "Allow"
		}]
	}`)
	err := schema.ValidateACLs(doc)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "operation") {
		t.Errorf("error should mention `operation`; got: %v", err)
	}
}

func TestValidatePlan_Valid(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"generated_at": "2026-05-21T10:05:00Z",
		"bindings": [], "unmapped": [], "rejected": [],
		"warnings": [], "deny_analysis": []
	}`)
	if err := schema.ValidatePlan(doc); err != nil {
		t.Fatalf("expected valid; got: %v", err)
	}
}

func TestValidateApplySummary_Valid(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"bindings": [
			{"binding_id":"rb-0123456789ab","principal":"User:alice","role":"DeveloperRead","status":"CREATED"}
		],
		"counts": {"total": 1, "created": 1, "skip_exists": 0, "failed": 0}
	}`)
	if err := schema.ValidateApplySummary(doc); err != nil {
		t.Fatalf("expected valid; got: %v", err)
	}
}

func TestValidateApplySummary_RejectsUnknownStatus(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"bindings": [
			{"binding_id":"rb-0123456789ab","principal":"User:alice","role":"DeveloperRead","status":"BOGUS"}
		],
		"counts": {"total": 1, "created": 0, "skip_exists": 0, "failed": 0}
	}`)
	if err := schema.ValidateApplySummary(doc); err == nil {
		t.Fatal("expected error for unknown status enum value")
	}
}

func TestValidateVerifySummary_Valid(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"plan_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"results": [
			{"binding_id":"rb-0123456789ab","source_acl_id":1,"status":"EFFECTIVE_OK"},
			{"binding_id":"rb-cdef01234567","source_acl_id":2,"status":"EFFECTIVE_MISSING","detail":"no binding"}
		],
		"counts": {"total": 2, "effective_ok": 1, "effective_missing": 1, "effective_unknown": 0}
	}`)
	if err := schema.ValidateVerifySummary(doc); err != nil {
		t.Fatalf("expected valid; got: %v", err)
	}
}

func TestValidateVerifySummary_RejectsMissingPlanSHA256(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"results": [],
		"counts": {"total": 0, "effective_ok": 0, "effective_missing": 0, "effective_unknown": 0}
	}`)
	if err := schema.ValidateVerifySummary(doc); err == nil {
		t.Fatal("expected error when plan_sha256 is missing")
	}
}

func TestValidateVerifySummary_RejectsMissingSchemaVersion(t *testing.T) {
	doc := []byte(`{
		"results": [],
		"counts": {"total": 0, "effective_ok": 0, "effective_missing": 0, "effective_unknown": 0}
	}`)
	if err := schema.ValidateVerifySummary(doc); err == nil {
		t.Fatal("expected error when schema_version is missing")
	}
}

func TestValidateStatusReport_Valid(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"run_dir": "/tmp/runs/2026-05-26T10:00:00Z-abc",
		"extract": {"present": true, "detail": {"acl_count": 12, "source": "json"}},
		"plan": {"present": true, "detail": {"bindings": 5, "unmapped": 0, "rejected": 0, "checksum_ok": true}},
		"verify": {"present": true, "detail": {"total": 5, "effective_ok": 5, "effective_missing": 0, "effective_unknown": 0}}
	}`)
	if err := schema.ValidateStatusReport(doc); err != nil {
		t.Fatalf("expected valid; got: %v", err)
	}
}

func TestValidateStatusReport_RejectsMissingRunDir(t *testing.T) {
	doc := []byte(`{"schema_version": "1"}`)
	if err := schema.ValidateStatusReport(doc); err == nil {
		t.Fatal("expected error when run_dir is missing")
	}
}

func TestValidateReportOutput_Valid(t *testing.T) {
	doc := []byte(`{
		"schema_version": "1",
		"plan": {
			"schema_version": "1",
			"generated_at": "2026-05-21T10:05:00Z",
			"bindings": [],
			"unmapped": [], "rejected": [], "warnings": [], "deny_analysis": []
		}
	}`)
	if err := schema.ValidateReportOutput(doc); err != nil {
		t.Fatalf("expected valid; got: %v", err)
	}
}

func TestValidateReportOutput_RejectsMissingPlan(t *testing.T) {
	doc := []byte(`{"schema_version": "1"}`)
	if err := schema.ValidateReportOutput(doc); err == nil {
		t.Fatal("expected error when plan is missing")
	}
}
