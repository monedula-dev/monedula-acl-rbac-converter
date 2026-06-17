// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package diff implements `monedula-acl-rbac diff` for comparing two ACL or
// plan files.
package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Format selects the output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// CurrentSchemaVersion is stamped into JSON envelopes emitted by ACLs
// and Plans, matching apply / verify / status / report convention. Bump
// when the envelope shape changes incompatibly.
const CurrentSchemaVersion = "1"

// ACLDiff is the JSON envelope returned by `diff --acls --format json`.
type ACLDiff struct {
	SchemaVersion string         `json:"schema_version"`
	Added         []types.ACLRow `json:"added"`
	Removed       []types.ACLRow `json:"removed"`
}

// PlanDiff is the JSON envelope returned by `diff --plan --format json`.
type PlanDiff struct {
	SchemaVersion string          `json:"schema_version"`
	Added         []types.Binding `json:"added"`
	Removed       []types.Binding `json:"removed"`
	Changed       []types.Binding `json:"changed"`
}

type aclKey struct {
	Principal      string
	Host           string
	Operation      types.Operation
	ResourceType   types.ResourceType
	ResourceName   string
	PatternType    types.PatternType
	PermissionType types.PermissionType
}

func keyOfACL(r types.ACLRow) aclKey {
	return aclKey{
		Principal:      r.Principal,
		Host:           r.Host,
		Operation:      r.Operation,
		ResourceType:   r.ResourceType,
		ResourceName:   r.ResourceName,
		PatternType:    r.PatternType,
		PermissionType: r.PermissionType,
	}
}

// ACLs writes the diff between two ACL sets.
func ACLs(w io.Writer, a, b []types.ACLRow, format Format) error {
	aSet := map[aclKey]types.ACLRow{}
	bSet := map[aclKey]types.ACLRow{}
	for _, r := range a {
		aSet[keyOfACL(r)] = r
	}
	for _, r := range b {
		bSet[keyOfACL(r)] = r
	}

	var added, removed []types.ACLRow
	for k, r := range bSet {
		if _, ok := aSet[k]; !ok {
			added = append(added, r)
		}
	}
	for k, r := range aSet {
		if _, ok := bSet[k]; !ok {
			removed = append(removed, r)
		}
	}

	if format == FormatJSON {
		// Empty slices should marshal as `[]` not `null` so downstream
		// consumers can iterate unconditionally.
		if added == nil {
			added = []types.ACLRow{}
		}
		if removed == nil {
			removed = []types.ACLRow{}
		}
		return json.NewEncoder(w).Encode(ACLDiff{
			SchemaVersion: CurrentSchemaVersion,
			Added:         added,
			Removed:       removed,
		})
	}
	for _, r := range added {
		fmt.Fprintf(w, "ADDED   %+v\n", r)
	}
	for _, r := range removed {
		fmt.Fprintf(w, "REMOVED %+v\n", r)
	}
	return nil
}

// Plans writes the diff between two plans (binding-level).
func Plans(w io.Writer, a, b types.Plan, format Format) error {
	aSet := map[string]types.Binding{}
	bSet := map[string]types.Binding{}
	for _, bd := range a.Bindings {
		aSet[bd.ID] = bd
	}
	for _, bd := range b.Bindings {
		bSet[bd.ID] = bd
	}

	var added, removed, changed []types.Binding
	for k, bd := range bSet {
		if _, ok := aSet[k]; !ok {
			added = append(added, bd)
		}
	}
	for k, bd := range aSet {
		other, ok := bSet[k]
		if !ok {
			removed = append(removed, bd)
			continue
		}
		// Compare full binding contents, not just (Action, Role). The earlier
		// check missed `Scope.*` and `ResourcePatterns` changes — `diff --plan`
		// after a hand-edit (or `plan --revalidate` + manual scope tweak)
		// would silently report "no change" and leave the operator with a
		// false sense of safety before `apply`. The binding ID is derived
		// from those fields in the normal planner output, but the operator-
		// override path (`plan --revalidate`) lets the invariant break, and
		// `diff` is exactly the tool meant to surface that.
		if !reflect.DeepEqual(bd, other) {
			changed = append(changed, other)
		}
	}

	if format == FormatJSON {
		if added == nil {
			added = []types.Binding{}
		}
		if removed == nil {
			removed = []types.Binding{}
		}
		if changed == nil {
			changed = []types.Binding{}
		}
		return json.NewEncoder(w).Encode(PlanDiff{
			SchemaVersion: CurrentSchemaVersion,
			Added:         added,
			Removed:       removed,
			Changed:       changed,
		})
	}
	for _, bd := range added {
		fmt.Fprintf(w, "ADDED   binding %s %s %s\n", bd.ID, bd.Role, bd.Principal)
	}
	for _, bd := range removed {
		fmt.Fprintf(w, "REMOVED binding %s %s %s\n", bd.ID, bd.Role, bd.Principal)
	}
	for _, bd := range changed {
		fmt.Fprintf(w, "CHANGED binding %s\n", bd.ID)
	}
	return nil
}
