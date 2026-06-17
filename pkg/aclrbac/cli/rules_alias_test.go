// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

func TestRulesDumpAlias(t *testing.T) {
	var buf bytes.Buffer
	stdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	exit := cli.Execute([]string{"rules", "dump"})
	w.Close()
	<-done
	if exit != 0 {
		t.Fatalf("rules dump exit %d", exit)
	}
	if !strings.Contains(buf.String(), "DeveloperRead") {
		t.Errorf("rules dump should print default rules; got %q", buf.String())
	}
}
