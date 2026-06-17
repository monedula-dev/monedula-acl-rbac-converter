// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package schema validates canonical IR documents (acls.json, plan.json)
// against the JSON Schemas shipped with the binary.
package schema

import "embed"

// embeddedSchemas is the schemas/ directory baked into the binary at build
// time, so the tool ships as a single static file.
//
//go:embed acls.v1.json plan.v1.json apply-summary.v1.json verify-summary.v1.json status.v1.json report.v1.json
var embeddedSchemas embed.FS
