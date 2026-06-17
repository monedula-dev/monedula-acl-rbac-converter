// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package version exposes the tool's release tag in a dependency-free
// location so non-CLI packages (e.g., delete-script generators) can stamp
// it into artefacts without importing the cobra-laden cli package and
// pulling in a circular dependency.
//
// Value is set at build time via -ldflags
// "-X github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/version.Version=vX.Y.Z".
// Falls back to "dev" for raw `go build` and to the module pseudo-version
// when installed via `go install ...@vX.Y.Z` (see cli.init for the
// BuildInfo lookup).
package version

// Version is the release tag the binary was built from.
var Version = "dev"
