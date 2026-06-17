// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// parsePrincipalFile reads a one-principal-per-line text file.
// Blank lines and #-prefixed comments are skipped; whitespace is
// trimmed per line. Returns the deduplicated principals (relative
// order preserved). Caller is responsible for merging with --principal
// values.
func parsePrincipalFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("--principal-file: read %s: %w", path, err)
	}
	defer f.Close()
	seen := make(map[string]struct{})
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("--principal-file: scan %s: %w", path, err)
	}
	return out, nil
}

// mergePrincipals combines flag and file principal lists, dropping duplicates.
// Relative order is preserved (flag values first, then file values).
func mergePrincipals(flagValues, fileValues []string) []string {
	seen := make(map[string]struct{}, len(flagValues)+len(fileValues))
	var out []string
	for _, src := range [][]string{flagValues, fileValues} {
		for _, p := range src {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}
