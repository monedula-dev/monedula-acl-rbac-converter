// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/authlogin"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/convert"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/diff"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/discover"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/listbindings"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/rulesshow"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cmds/status"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Authentication helpers"}
	cmd.AddCommand(newAuthLoginCmd())
	return cmd
}

func newAuthLoginCmd() *cobra.Command {
	var mdsAuth MDSAuthFlags
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Interactive MDS login; writes token cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			return authlogin.Run(authlogin.Options{
				URL:                mdsAuth.URL,
				CACertPath:         mdsAuth.CACertPath,
				ClientCertPath:     mdsAuth.ClientCertPath,
				ClientKeyPath:      mdsAuth.ClientKeyPath,
				InsecureSkipVerify: mdsAuth.InsecureSkipVerify,
			})
		},
	}
	// auth login resolves the token itself (prompting for the username), so it
	// only needs the connection flags — not the token-resolution flags it
	// would otherwise advertise and ignore.
	mdsAuth.AddMDSConnFlags(cmd)
	return cmd
}

func newDiscoverCmd() *cobra.Command {
	var (
		outPath string
	)
	var mdsAuth MDSAuthFlags
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Query MDS for cluster IDs and emit a scopes.yaml stub",
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := mdsAuth.ResolveClient()
			if err != nil {
				return err
			}
			var w io.Writer = os.Stdout
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return discover.Run(w, cl)
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "", "Output path (default: stdout)")
	mdsAuth.AddMDSAuthFlags(cmd)
	return cmd
}

func newStatusCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "status RUNDIR",
		Short: "Summarize the state of a run directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch format {
			case "", "text", "json":
			default:
				return NewUsageError(fmt.Sprintf("status: unknown --format %q (allowed: text, json)", format))
			}
			f := status.Format(format)
			if format == "" {
				f = status.FormatText
			}
			return status.Run(os.Stdout, args[0], f)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "text|json")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var (
		aclsPair []string
		planPair []string
		format   string
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two acls.json or two plan.json files",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch format {
			case "", "text", "json":
			default:
				return NewUsageError(fmt.Sprintf("diff: unknown --format %q (allowed: text, json)", format))
			}
			if len(aclsPair) > 0 && len(planPair) > 0 {
				return NewUsageError("diff: --acls and --plan are mutually exclusive")
			}
			if len(aclsPair) == 2 {
				a, err := rundir.ReadACLs(aclsPair[0])
				if err != nil {
					return err
				}
				b, err := rundir.ReadACLs(aclsPair[1])
				if err != nil {
					return err
				}
				return diff.ACLs(os.Stdout, a.ACLs, b.ACLs, diffFormat(format))
			}
			if len(planPair) == 2 {
				a, err := rundir.ReadPlan(planPair[0])
				if err != nil {
					return err
				}
				b, err := rundir.ReadPlan(planPair[1])
				if err != nil {
					return err
				}
				return diff.Plans(os.Stdout, a, b, diffFormat(format))
			}
			return NewUsageError("--acls A B or --plan A B is required")
		},
	}
	cmd.Flags().StringSliceVar(&aclsPair, "acls", nil, "Two acls.json paths to compare")
	cmd.Flags().StringSliceVar(&planPair, "plan", nil, "Two plan.json paths to compare")
	cmd.Flags().StringVar(&format, "format", "text", "text|json")
	return cmd
}

func diffFormat(f string) diff.Format {
	if f == "json" {
		return diff.FormatJSON
	}
	return diff.FormatText
}

func newMDSCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "mds", Short: "MDS subcommands"}
	cmd.AddCommand(newMDSListBindingsCmd())
	return cmd
}

func newMDSListBindingsCmd() *cobra.Command {
	var (
		principalFilter []string
		scopeFilter     []string
		format          string
		kafkaCluster    string
		srCluster       string
		ksqlCluster     string
		connectCluster  string
	)
	var mdsAuth MDSAuthFlags
	cmd := &cobra.Command{
		Use:   "list-bindings",
		Short: "Read-only inventory of existing role bindings in MDS",
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := mdsAuth.ResolveClient()
			if err != nil {
				return err
			}
			f := listbindings.Format(format)
			if format == "" {
				f = listbindings.FormatText
			}
			return listbindings.Run(os.Stdout, listbindings.Options{
				Client:          cl,
				PrincipalFilter: principalFilter,
				ScopeFilter:     scopeFilter,
				Scope: types.Scope{
					KafkaCluster:          kafkaCluster,
					SchemaRegistryCluster: srCluster,
					KSQLCluster:           ksqlCluster,
					ConnectCluster:        connectCluster,
				},
				Format: f,
			})
		},
	}
	cmd.Flags().StringSliceVar(&principalFilter, "principal-filter", nil, "Principal filter, repeatable (required: MDS has no all-principals lookup)")
	cmd.Flags().StringSliceVar(&scopeFilter, "scope-filter", nil, "Scope filter (repeatable)")
	cmd.Flags().StringVar(&kafkaCluster, "kafka-cluster", "", "Kafka cluster ID for the lookup scope")
	cmd.Flags().StringVar(&srCluster, "schema-registry-cluster", "", "Schema Registry cluster ID for the lookup scope")
	cmd.Flags().StringVar(&ksqlCluster, "ksql-cluster", "", "ksqlDB cluster ID for the lookup scope")
	cmd.Flags().StringVar(&connectCluster, "connect-cluster", "", "Connect cluster ID for the lookup scope")
	cmd.Flags().StringVar(&format, "format", "text", "text|json|yaml")
	mdsAuth.AddMDSAuthFlags(cmd)
	return cmd
}

func newConvertCmd() *cobra.Command {
	var (
		from           string
		inputPath      string
		scopesPath     string
		rulesPath      string
		principalsPath string
		emitFormat     string
		outPath        string
		varsFile       string
		ignoreNonAdd   bool
		cfkNamespace   string
		cfkNameSalt    string
	)
	cmd := &cobra.Command{
		Use:   "convert",
		Short: "Stateless extract -> plan -> emit in one call",
		Long: `One-shot file-to-file conversion for exploration and small batches:
read ACLs from --input, plan against --scopes (and optional rules /
principals), and emit the result to --out (default stdout).

This is the fast path. It does NOT create a run directory, does NOT
apply anything to MDS, does NOT verify, and does NOT support live or
k8s sources (those need state). Production migrations should use the
explicit pipeline: extract -> plan -> apply -> verify -> delete-acls.

Source detection: --from is required for live/k8s/cfk directories;
otherwise the file extension chooses (.yaml/.yml -> yaml, .json -> json,
.csv -> csv, .sh -> script, .txt -> text).

Example:
  monedula-acl-rbac convert \
    --from yaml --input acls.yaml \
    --scopes scopes.yaml --rules rules.yaml \
    --format script \
    > bindings.sh`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var w io.Writer = os.Stdout
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return convert.Run(w, convert.Options{
				From:           from,
				InputPath:      inputPath,
				ScopesPath:     scopesPath,
				RulesPath:      rulesPath,
				PrincipalsPath: principalsPath,
				EmitFormat:     emitFormat,
				VarsFile:       varsFile,
				IgnoreNonAdd:   ignoreNonAdd,
				CFKNamespace:   cfkNamespace,
				CFKNameSalt:    cfkNameSalt,
			})
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "text|json|yaml|csv|strimzi|cfk|script (use extract+plan workflow for live/k8s)")
	cmd.Flags().StringVar(&inputPath, "input", "", "Input file path")
	cmd.Flags().StringVar(&scopesPath, "scopes", "", "scopes.yaml (required)")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "Optional rules.yaml")
	cmd.Flags().StringVar(&principalsPath, "principals", "", "Optional principals.yaml")
	cmd.Flags().StringVar(&emitFormat, "format", "script", "script|cfk|mds-curl")
	cmd.Flags().StringVar(&outPath, "out", "", "Output path (default: stdout)")
	cmd.Flags().StringVar(&varsFile, "vars", "", "Script source: vars.yaml for variable substitution")
	cmd.Flags().BoolVar(&ignoreNonAdd, "ignore-non-add", false, "Script source: skip --remove/--list invocations")
	cmd.Flags().StringVar(&cfkNamespace, "cfk-namespace", "", "CFK ConfluentRolebinding namespace (cfk emit format)")
	cmd.Flags().StringVar(&cfkNameSalt, "cfk-name-salt", "", "Salt mixed into binding IDs")
	return cmd
}

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Mapping rules management"}
	showCmd := newRulesShowCmd()
	cmd.AddCommand(showCmd)
	dumpCmd := &cobra.Command{
		Use:    "dump",
		Hidden: true,
		Short:  "Deprecated alias for `rules show`",
		RunE:   showCmd.RunE,
	}
	cmd.AddCommand(dumpCmd)
	return cmd
}

func newRulesShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the embedded default mapping rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rulesshow.Run(os.Stdout)
		},
	}
	return cmd
}
