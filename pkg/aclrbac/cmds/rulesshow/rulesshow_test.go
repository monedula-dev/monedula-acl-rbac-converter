// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package rulesshow_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/rulesshow"
)

func TestRun_PrintsEmbeddedDefaults(t *testing.T) {
	var buf bytes.Buffer
	if err := rulesshow.Run(&buf); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "DeveloperRead") {
		t.Errorf("output missing DeveloperRead:\n%s", out)
	}
	if !strings.Contains(out, "operations_mode") {
		t.Errorf("output missing operations_mode field:\n%s", out)
	}
}
