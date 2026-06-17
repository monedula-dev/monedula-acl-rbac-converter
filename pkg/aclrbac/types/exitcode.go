// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package types holds the canonical IR and shared value types used across the
// monedula-acl-rbac library. The types are deliberately small, value-only, and
// free of I/O so the library can be re-used by future Grafana plugins.
package types

// ExitCode mirrors the table in §5.4 of the design doc.
type ExitCode int

const (
	// ExitSuccess: normal completion.
	ExitSuccess ExitCode = 0
	// ExitUsage: missing required flag, malformed arg, unknown subcommand.
	ExitUsage ExitCode = 1
	// ExitInput: unparseable ACLs or malformed config files.
	ExitInput ExitCode = 2
	// ExitPlan: plan has unresolved unmapped/rejected items.
	ExitPlan ExitCode = 3
	// ExitExternal: MDS, Kafka, or Kubernetes unreachable / auth failure.
	ExitExternal ExitCode = 4
	// ExitGuardrail: destructive op refused (stale checksum, lockfile held,
	// wildcard-principal DENY classified UNKNOWN, etc.).
	ExitGuardrail ExitCode = 5
)
