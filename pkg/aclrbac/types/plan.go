// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package types

// Action is what `apply` will do with a binding entry.
type Action string

const (
	// ActionCreate: binding will be created by `apply`.
	ActionCreate Action = "CREATE"
	// ActionSkipExists: an equivalent binding already exists in MDS or in the
	// CFK existing-bindings.json sidecar; `apply` is a no-op for this entry.
	ActionSkipExists Action = "SKIP_EXISTS"
)

// DenyAnalysisStatus is the per-DENY classification produced by the planner.
type DenyAnalysisStatus string

const (
	DenySafeToRemove     DenyAnalysisStatus = "SAFE_TO_REMOVE"
	DenyWouldGrantAccess DenyAnalysisStatus = "WOULD_GRANT_ACCESS"
	DenyUnknown          DenyAnalysisStatus = "UNKNOWN"
)

// Scope is the RBAC scope a binding applies to. Only fields needed by the
// actual bindings are required; the rest may be empty. Validated against
// scopes.yaml in §5.1.
type Scope struct {
	Organization          string `json:"organization,omitempty"`
	Environment           string `json:"environment,omitempty"`
	KafkaCluster          string `json:"kafka_cluster,omitempty"`
	SchemaRegistryCluster string `json:"schema_registry_cluster,omitempty"`
	KSQLCluster           string `json:"ksql_cluster,omitempty"`
	ConnectCluster        string `json:"connect_cluster,omitempty"`
}

// ResourcePattern is how a binding addresses a resource. Pattern type is
// preserved end-to-end from the source ACL (spec §3.3 invariant).
type ResourcePattern struct {
	ResourceType ResourceType `json:"resource_type"`
	Name         string       `json:"name"`
	PatternType  PatternType  `json:"pattern_type"`
}

// Binding is a single RBAC role binding the planner produced from one or more
// source ACL rows.
type Binding struct {
	// Stable hash derived from (principal, role, scope, resource patterns).
	ID string `json:"id"`
	// Action `apply` will take.
	Action Action `json:"action"`
	// Resolved principal (after principals.yaml mapping).
	Principal string `json:"principal"`
	// Confluent RBAC role name (e.g., "DeveloperRead", "ResourceOwner").
	Role string `json:"role"`
	// RBAC scope. At least one cluster field must be set.
	Scope Scope `json:"scope"`
	// Resource patterns the binding covers.
	ResourcePatterns []ResourcePattern `json:"resource_patterns"`
	// All source ACL row IDs that contributed to this binding (includes
	// duplicates and rows expanded from `ALL`).
	SourceACLIDs []int `json:"source_acl_ids"`
}

// UnmappedEntry records an ACL group that did not match any rule.
type UnmappedEntry struct {
	SourceACLIDs []int  `json:"source_acl_ids"`
	Reason       string `json:"reason"` // e.g., "NO_RULE_MATCH", "HOST_RESTRICTED", "CONFLICTING_EXISTING_BINDING"
	Detail       string `json:"detail,omitempty"`
}

// RejectedEntry is an ACL group the planner refuses to convert (DENY ACLs are
// the main case).
type RejectedEntry struct {
	SourceACLIDs []int  `json:"source_acl_ids"`
	Reason       string `json:"reason"` // e.g., "DENY_PERMISSION"
	Detail       string `json:"detail,omitempty"`
}

// Warning surfaces operationally important conditions that don't block.
type Warning struct {
	Code   string `json:"code"` // e.g., "MTLS_DN_PASS_THROUGH", "LONE_CREATE_ON_CLUSTER", "CONFLICTING_EXISTING_BINDING"
	Detail string `json:"detail"`
}

// DenyAnalysisEntry holds the SAFE_TO_REMOVE / WOULD_GRANT_ACCESS / UNKNOWN
// classification of a single source DENY ACL row.
type DenyAnalysisEntry struct {
	SourceACLID int                `json:"source_acl_id"`
	Status      DenyAnalysisStatus `json:"status"`
	// For WOULD_GRANT_ACCESS, the rule (Allow ACL or RBAC binding) that
	// would still grant the access this DENY was protecting against.
	CoveringRule string `json:"covering_rule,omitempty"`
}

// Plan is the top-level document written as plan.json.
//
// SchemaVersion is a string ("1") for parity with the envelopes
// emitted by apply / verify / status / report --format json.
type Plan struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"` // RFC 3339 UTC
	// AclsSHA256 is the SHA-256 of the acls.json this plan was built from,
	// stamped by the CLI at plan time. The destructive delete commands
	// re-verify it so a regenerated or hand-edited acls.json cannot feed
	// different kafka-acls argv than the plan was analyzed against. Empty for
	// plans produced without a known acls.json path (e.g. one-shot convert).
	AclsSHA256   string              `json:"acls_sha256,omitempty"`
	Bindings     []Binding           `json:"bindings"`
	Unmapped     []UnmappedEntry     `json:"unmapped"`
	Rejected     []RejectedEntry     `json:"rejected"`
	Warnings     []Warning           `json:"warnings"`
	DenyAnalysis []DenyAnalysisEntry `json:"deny_analysis"`
}
