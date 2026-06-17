// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Command validate-schemas compiles every JSON Schema in schemas/ and
// reports compile errors. Catches malformed schemas in CI before they
// reach pkg/aclrbac/schema/embed.go's init() panic at binary start time.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func main() {
	root := "schemas"
	var failed int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		compiler := jsonschema.NewCompiler()
		if _, err := compiler.Compile(path); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "FAIL %s\n  %v\n", path, err)
			return nil
		}
		fmt.Println("OK  ", path)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk:", err)
		os.Exit(1)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d schema(s) failed to compile\n", failed)
		os.Exit(1)
	}
}
