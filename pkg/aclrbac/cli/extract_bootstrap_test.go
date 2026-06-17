// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli"
)

// TestKafkaAuth_ExplicitBootstrapAliasBeatsEnv pins that an explicit
// --bootstrap on the command line wins over the
// MONEDULA_ACL_RBAC_BOOTSTRAP_SERVER environment default. Because the env var
// was baked in as the --bootstrap-server flag default, the alias copy was
// gated on BootstrapServer == "" and so was silently discarded whenever the
// env var was set — the destructive delete scripts could then target the
// wrong cluster.
func TestKafkaAuth_ExplicitBootstrapAliasBeatsEnv(t *testing.T) {
	t.Setenv("MONEDULA_ACL_RBAC_BOOTSTRAP_SERVER", "env-cluster:9092")
	var f cli.KafkaAuthFlags
	cmd := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
	f.AddKafkaAuthFlags(cmd)
	cmd.SetArgs([]string{"--bootstrap", "explicit:9093"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if f.BootstrapServer != "explicit:9093" {
		t.Errorf("explicit --bootstrap must beat the env default; got %q", f.BootstrapServer)
	}
}

// TestExtract_BootstrapAlias_CLI verifies that the --bootstrap flag is
// accepted as an alias for --bootstrap-server at the CLI layer. We use an
// unreachable broker so we don't need to spin up kfake; the only assertion
// is that Cobra did not report "unknown flag: --bootstrap". A connection
// failure is expected (and fine) — we capture stderr to distinguish a
// Cobra usage error from a network error.
func TestExtract_BootstrapAlias_CLI(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "acls.json")

	stderr := captureStderr(t, func() {
		cli.Execute([]string{
			"extract", "--from", "live",
			"--bootstrap", "127.0.0.1:1",
			"--out", out,
		})
	})

	// If --bootstrap is unknown, Cobra prints "unknown flag: --bootstrap".
	if strings.Contains(stderr, "unknown flag") && strings.Contains(stderr, "bootstrap") {
		t.Fatalf("--bootstrap alias not recognized by Cobra; stderr:\n%s", stderr)
	}
	_ = os.Remove(out)
}
