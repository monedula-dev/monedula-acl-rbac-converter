// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package cli wires every monedula-acl-rbac subcommand onto a cobra tree.
//
// The Execute function is the single entry point: cmd/monedula-acl-rbac/main.go
// passes os.Args[1:] in and the integer exit code out.
package cli

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/version"
)

// Version, Commit, and Date are set at build time via -ldflags by
// goreleaser and Makefile builds. When the binary is produced by
// `go install <module>@vX.Y.Z`, ldflags aren't injected; we fall back
// to the values Go 1.18+ embeds automatically in BuildInfo, so
// `--version` still reports useful provenance instead of "dev".
//
// Version is sourced from the version subpackage so non-cli code (the
// delete-script generators in particular) can stamp the same value into
// their artefacts without importing this cobra-heavy package.
var (
	Commit = ""
	Date   = ""
)

func init() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if version.Version == "dev" {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			version.Version = v
		}
	}
	if Commit == "" || Date == "" {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if Commit == "" && s.Value != "" {
					Commit = s.Value
					if len(Commit) > 12 {
						Commit = Commit[:12]
					}
				}
			case "vcs.time":
				if Date == "" {
					Date = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" && Commit != "" && !strings.HasSuffix(Commit, "-dirty") {
					Commit += "-dirty"
				}
			}
		}
	}
}

// versionTemplate is rendered by cobra when --version is passed. We
// extend the default ("{{.Use}} version {{.Version}}") to include the
// commit + build date when they are known. Operators can read it back
// off a deployed binary to confirm exactly what they're running.
const versionTemplate = `{{with .Name}}{{printf "%s " .}}{{end}}{{printf "version %s" .Version}}` +
	" (commit {{.Annotations.commit}}, built {{.Annotations.date}})\n"

// Execute runs the CLI with the given args (excluding argv[0]) and returns
// the exit code defined in spec §5.4.
func Execute(args []string) int {
	root := newRoot()
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return int(MapError(err))
	}
	return int(types.ExitSuccess)
}

func newRoot() *cobra.Command {
	var (
		logFormat string
		logLevel  string
	)
	root := &cobra.Command{
		Use:           "monedula-acl-rbac",
		Short:         "Convert Apache Kafka ACLs to Confluent RBAC role bindings",
		Long:          longRootDescription,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		Annotations: map[string]string{
			"commit": orPlaceholder(Commit, "unknown"),
			"date":   orPlaceholder(Date, "unknown"),
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return log.Init(log.Format(logFormat), logLevel)
		},
	}
	// Flag-parse failures (unknown flag, missing flag value) are usage errors
	// (exit 1), not "external" (exit 4). FlagErrorFunc is inherited by
	// subcommands, so setting it on root covers the whole tree.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return NewUsageError(err.Error())
	})
	root.SetVersionTemplate(versionTemplate)
	root.PersistentFlags().StringVar(&logFormat, "log-format", envOr("MONEDULA_ACL_RBAC_LOG_FORMAT", "text"), "Log output format (text|json)")
	root.PersistentFlags().StringVar(&logLevel, "log-level", envOr("MONEDULA_ACL_RBAC_LOG_LEVEL", "info"), "Log level (debug|info|warn|error)")

	root.AddCommand(
		newExtractCmd(),
		newPlanCmd(),
		newReportCmd(),
		newEmitCmd(),
		newApplyCmd(),
		newVerifyCmd(),
		newDeleteACLsCmd(),
		newDeleteDenyACLsCmd(),
		newDeleteDenyOneCmd(),
		newAuthCmd(),
		newDiscoverCmd(),
		newStatusCmd(),
		newDiffCmd(),
		newMDSCmd(),
		newConvertCmd(),
		newRulesCmd(),
		newInitCmd(),
	)
	return root
}

func orPlaceholder(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

const longRootDescription = `monedula-acl-rbac converts Apache Kafka ACLs into Confluent RBAC role
bindings with strong safety guarantees: dry-run defaults, run-directory
audit trail, script-first deletion, effective-access verification, and
DENY-removal safety checks.

The recommended migration workflow (matches the README checklist):

  1. discover     bootstrap a scopes.yaml from MDS
  2. extract      read ACLs from a source into acls.json
  3. plan         produce plan.json + report.txt
  4. apply        preview with --dry-run, then create bindings with --confirm
  5. verify       confirm users actually have access (default: effective mode)
  6. delete-acls  after an operator-judgement cooldown (typically 24h),
                  generate a per-principal deletion script you inspect and run
  7. delete-deny-acls  if the source had DENY ACLs (which never auto-convert),
                  generate a separate, multi-gated script to remove them once
                  you have confirmed access no longer depends on them

See https://github.com/monedula-dev/monedula-acl-rbac-converter for the
full spec and README.`
