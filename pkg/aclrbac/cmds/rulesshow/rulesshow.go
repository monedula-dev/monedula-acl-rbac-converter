// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package rulesshow implements `monedula-acl-rbac rules show`.
package rulesshow

import (
	"io"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
)

// Run writes the embedded default rules.yaml to w.
func Run(w io.Writer) error {
	data, err := config.DefaultRulesYAML()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
