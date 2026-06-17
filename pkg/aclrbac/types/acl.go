// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types

// Operation is a Kafka ACL operation (matches Apache Kafka's AclOperation enum).
type Operation string

const (
	OpRead            Operation = "Read"
	OpWrite           Operation = "Write"
	OpCreate          Operation = "Create"
	OpDelete          Operation = "Delete"
	OpAlter           Operation = "Alter"
	OpDescribe        Operation = "Describe"
	OpClusterAction   Operation = "ClusterAction"
	OpDescribeConfigs Operation = "DescribeConfigs"
	OpAlterConfigs    Operation = "AlterConfigs"
	OpIdempotentWrite Operation = "IdempotentWrite"
	OpAll             Operation = "All"
)

// ResourceType is a Kafka ACL resource type.
type ResourceType string

const (
	ResourceCluster         ResourceType = "Cluster"
	ResourceTopic           ResourceType = "Topic"
	ResourceGroup           ResourceType = "Group"
	ResourceTransactionalID ResourceType = "TransactionalId"
	ResourceDelegationToken ResourceType = "DelegationToken"
	ResourceSubject         ResourceType = "Subject" // Schema Registry
)

// PatternType is how a resource name is matched. LITERAL and PREFIXED are the
// only types Kafka supports outside the deprecated MATCH/ANY.
type PatternType string

const (
	PatternLiteral  PatternType = "LITERAL"
	PatternPrefixed PatternType = "PREFIXED"
)

// PermissionType is Allow or Deny. DENY conversion is blocked by the planner
// (see spec §3.1); the field is preserved so the report can show the original.
type PermissionType string

const (
	PermissionAllow PermissionType = "Allow"
	PermissionDeny  PermissionType = "Deny"
)

// ACLRow is the canonical IR for one Kafka ACL row.
type ACLRow struct {
	ID             int            `json:"id"`
	Principal      string         `json:"principal"`
	Host           string         `json:"host"`
	Operation      Operation      `json:"operation"`
	ResourceType   ResourceType   `json:"resource_type"`
	ResourceName   string         `json:"resource_name"`
	PatternType    PatternType    `json:"pattern_type"`
	PermissionType PermissionType `json:"permission_type"`
}

// ACLSetSource records where an ACLSet came from. Carried into plan.json and
// the run directory's audit trail.
type ACLSetSource struct {
	Type        string `json:"type"`         // "live", "text", "json", "yaml", "csv", "strimzi", "cfk", "k8s", "script"
	GeneratedAt string `json:"generated_at"` // RFC 3339 UTC
}

// ACLSet is the top-level document written as acls.json.
//
// SchemaVersion is a string ("1") for parity with the envelopes
// emitted by apply / verify / status / report --format json. Stored as
// a string so later versions have semver-ish headroom ("1.1" etc.).
type ACLSet struct {
	SchemaVersion string       `json:"schema_version"`
	Source        ACLSetSource `json:"source"`
	ACLs          []ACLRow     `json:"acls"`
}
