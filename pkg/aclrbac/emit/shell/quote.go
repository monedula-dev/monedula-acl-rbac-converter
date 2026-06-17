// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package shell holds shell-safe formatting helpers used by every generated
// script. Single-quote quoting is mandatory per the spec §4.3 script-safety
// contract.
package shell

import "strings"

// Quote wraps s in single quotes, escaping each embedded single quote via the
// canonical close-quote / escaped-quote / reopen idiom:
//
//	'  ->  '\''
//
// This is safe in POSIX sh / bash: single-quoted strings forbid interpolation
// entirely, so `$VAR`, backticks, and backslashes pass through verbatim.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
