// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rundir

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// WriteACLs marshals set to JSON, validates against the schema, then writes
// to path. The directory must already exist (call Ensure).
//
// Beyond the JSON schema, this also rejects any row whose Principal/Host/
// ResourceName contains a control character — those fields flow into the
// generated bash script's `#` comment header verbatim, and a '\n' would
// escape the comment and execute as bash at script-run time. See
// types.ValidateACLSet.
func WriteACLs(path string, set types.ACLSet) error {
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal acls: %w", err)
	}
	if err := schema.ValidateACLs(data); err != nil {
		return fmt.Errorf("validate acls before write: %w", err)
	}
	if err := types.ValidateACLSet(set); err != nil {
		return fmt.Errorf("validate acls before write: %w", err)
	}
	if err := WriteAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ReadACLs reads and schema-validates an acls.json file. It also re-runs
// types.ValidateACLSet so a hand-edited file with control characters in
// Principal/Host/ResourceName is refused (the JSON schema cannot express
// that constraint in a way that survives older drafts).
func ReadACLs(path string) (types.ACLSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return types.ACLSet{}, fmt.Errorf("read %s: %w", path, err)
	}
	if err := schema.ValidateACLs(data); err != nil {
		return types.ACLSet{}, fmt.Errorf("validate %s: %w", path, err)
	}
	var set types.ACLSet
	if err := json.Unmarshal(data, &set); err != nil {
		return types.ACLSet{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := types.ValidateACLSet(set); err != nil {
		return types.ACLSet{}, fmt.Errorf("validate %s: %w", path, err)
	}
	return set, nil
}

// WritePlan marshals plan to JSON, validates, then writes to path. In
// addition to the JSON schema, rejects any Binding whose free-text fields
// (Principal, Role, Scope.*, ResourcePatterns[].Name) contains a control
// character — the same defence as types.ValidateACLSet applied to the
// downstream side. See types.ValidatePlan.
func WritePlan(path string, plan types.Plan) error {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}
	if err := schema.ValidatePlan(data); err != nil {
		return fmt.Errorf("validate plan before write: %w", err)
	}
	if err := types.ValidatePlan(plan); err != nil {
		return fmt.Errorf("validate plan before write: %w", err)
	}
	if err := WriteAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ReadPlan reads and schema-validates a plan.json file, plus re-runs
// types.ValidatePlan to refuse a hand-edited file with control chars in
// binding fields.
func ReadPlan(path string) (types.Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return types.Plan{}, fmt.Errorf("read %s: %w", path, err)
	}
	if err := schema.ValidatePlan(data); err != nil {
		return types.Plan{}, fmt.Errorf("validate %s: %w", path, err)
	}
	var plan types.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return types.Plan{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := types.ValidatePlan(plan); err != nil {
		return types.Plan{}, fmt.Errorf("validate %s: %w", path, err)
	}
	return plan, nil
}

// WriteRawForTest is exported only for test fixtures that want to write
// invalid bytes to test the read-side schema check. Production code should
// not call this.
func WriteRawForTest(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
