// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package main

import (
	"fmt"
	"os"
)

func main() {
	failed := false
	for _, p := range []string{"bin", "coverage.out", "coverage.html"} {
		if err := os.RemoveAll(p); err != nil {
			fmt.Fprintln(os.Stderr, "clean:", err)
			failed = true
		}
	}
	if failed {
		// Exit non-zero so `make clean` doesn't report success while a target
		// (e.g. bin/ holding an open exe on Windows) was not removed.
		os.Exit(1)
	}
}
