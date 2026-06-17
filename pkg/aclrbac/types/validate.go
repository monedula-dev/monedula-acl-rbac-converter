// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types

import "fmt"

// ValidateACLSet rejects any ACLRow whose free-text fields (Principal, Host,
// ResourceName) contain a control character (anything < 0x20 or 0x7f).
//
// This is the input-side half of the shell-script-injection defence. The
// generated delete-*.sh and rollback-*.sh scripts interpolate those fields
// into bash — most slots are shell.Quote'd, but the header comment block
// (`# bootstrap-server: %s`, `#   <principal>`, `# Run directory: %s`) writes
// raw `%s`. A '\n' there breaks out of the `#` comment and is interpreted as
// a bash line at script-execution time, before any guard or trap fires.
// rundir.WriteACLs and rundir.ReadACLs both call this so a crafted source
// (`extract --from text/csv/...` with a tampered input) and a hand-edited
// acls.json are both refused. Schema validation already constrains enum
// fields (Operation, ResourceType, PatternType, PermissionType), so this
// function only covers the free-text trio.
//
// Returns the first error found; nil if all rows are clean.
func ValidateACLSet(set ACLSet) error {
	for _, r := range set.ACLs {
		if err := ValidateACLRow(r); err != nil {
			return err
		}
	}
	return nil
}

// ValidateACLRow checks a single row. See ValidateACLSet.
func ValidateACLRow(r ACLRow) error {
	if i, c := firstControl(r.Principal); i >= 0 {
		return fmt.Errorf("acl_id=%d: principal contains control character U+%04X at byte %d", r.ID, c, i)
	}
	if i, c := firstControl(r.Host); i >= 0 {
		return fmt.Errorf("acl_id=%d: host contains control character U+%04X at byte %d", r.ID, c, i)
	}
	if i, c := firstControl(r.ResourceName); i >= 0 {
		return fmt.Errorf("acl_id=%d: resource_name contains control character U+%04X at byte %d", r.ID, c, i)
	}
	return nil
}

// firstControl returns the byte offset and rune of the first control
// character in s, or (-1, 0) if there isn't one. Control characters are
// runes < 0x20 (C0 controls — incl. NUL, TAB, LF, CR) and 0x7F (DEL).
func firstControl(s string) (int, rune) {
	for i, r := range s {
		if r < 0x20 || r == 0x7f {
			return i, r
		}
	}
	return -1, 0
}

// ValidatePlan rejects any Binding whose free-text fields contain a control
// character. Plan bindings feed the CFK YAML emitter, the mds-curl emitter,
// and the apply path's POST bodies — a '\n' or '\x00' in Principal / Role /
// Scope.* / ResourcePattern.Name would inject sibling YAML keys, break out
// of an HTTP header, or escape a shell comment depending on the consumer.
// types.ValidateACLSet covers the upstream ACL inputs; this is the symmetric
// gate for the downstream Plan a hand-edit could have crafted.
func ValidatePlan(p Plan) error {
	for i, b := range p.Bindings {
		if err := validateBinding(b); err != nil {
			return fmt.Errorf("binding[%d] id=%s: %w", i, b.ID, err)
		}
	}
	return nil
}

func validateBinding(b Binding) error {
	if i, c := firstControl(b.Principal); i >= 0 {
		return fmt.Errorf("principal contains control character U+%04X at byte %d", c, i)
	}
	if i, c := firstControl(b.Role); i >= 0 {
		return fmt.Errorf("role contains control character U+%04X at byte %d", c, i)
	}
	for _, s := range []struct{ field, val string }{
		{"scope.organization", b.Scope.Organization},
		{"scope.environment", b.Scope.Environment},
		{"scope.kafka_cluster", b.Scope.KafkaCluster},
		{"scope.schema_registry_cluster", b.Scope.SchemaRegistryCluster},
		{"scope.ksql_cluster", b.Scope.KSQLCluster},
		{"scope.connect_cluster", b.Scope.ConnectCluster},
	} {
		if i, c := firstControl(s.val); i >= 0 {
			return fmt.Errorf("%s contains control character U+%04X at byte %d", s.field, c, i)
		}
	}
	for j, rp := range b.ResourcePatterns {
		if i, c := firstControl(rp.Name); i >= 0 {
			return fmt.Errorf("resource_patterns[%d].name contains control character U+%04X at byte %d", j, c, i)
		}
	}
	return nil
}
