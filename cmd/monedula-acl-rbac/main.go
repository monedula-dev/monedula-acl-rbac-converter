// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Command monedula-acl-rbac is the CLI entry point. All logic lives in
// pkg/aclrbac/cli — this file exists solely so the binary's import path
// matches the project name.
package main

import (
	"os"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
