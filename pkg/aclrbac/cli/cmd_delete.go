// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/acls"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/deny"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

func newDeleteACLsCmd() *cobra.Command {
	var (
		planPath        string
		verifyPath      string
		principals      []string
		principalFilter []string
		principalFile   string
		confirmFlag     bool
		understandDestr bool
	)
	var kaf KafkaAuthFlags
	var rdf RunDirFlags

	cmd := &cobra.Command{
		Use:   "delete-acls",
		Short: "Generate the source-ACL deletion script",
		Long: `Remove the source ACLs that 'apply' converted, once 'verify' has
confirmed every one of them is EFFECTIVE_OK. Destructive.

Emits a 'kafka-acls --remove' bash script in the run directory plus a
symmetric rollback.sh; you inspect, then run them by hand. The tool
never executes the deletion itself — every destructive change goes
through a reviewable script.

Guardrails (all enforced):
  - 'verify' must be present (--verify)
  - every source ACL must be EFFECTIVE_OK in verify.json
  - --principal (or --principal-file) restricts the deletion scope
  - --confirm AND --i-understand-this-is-destructive required either way

Example:
  monedula-acl-rbac delete-acls \
    --plan runs/.../plan.json --verify runs/.../verify.json \
    --bootstrap-server kafka.example.com:9093 \
    --command-config admin.properties \
    --principal User:alice --principal User:bob \
    --confirm --i-understand-this-is-destructive

Outputs: delete-acls.sh (the deletion script), deleted-acls.json,
rollback.sh, delete.log.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if planPath == "" || verifyPath == "" {
				return NewUsageError("--plan and --verify are required")
			}
			if !understandDestr {
				return NewUsageError("--i-understand-this-is-destructive is required")
			}
			principals = mergePrincipals(principals, principalFilter)
			if principalFile != "" {
				filePrincipals, perr := parsePrincipalFile(principalFile)
				if perr != nil {
					return NewInputError(perr.Error())
				}
				principals = mergePrincipals(principals, filePrincipals)
			}
			if !confirmFlag {
				ok, err := Confirm(ConfirmInput{
					IsTTY:   StdinIsTTY(),
					Stdin:   os.Stdin,
					Summary: fmt.Sprintf("Generate deletion script from %s", planPath),
				})
				if err != nil {
					return err
				}
				if !ok {
					return NewUsageError("not confirmed")
				}
			}
			runDir, err := rdf.Resolve(planPath)
			if err != nil {
				return err
			}
			aclsPath := filepath.Join(runDir, "acls.json")

			vsum, err := readVerifySummary(verifyPath)
			if err != nil {
				return NewInputError(err.Error())
			}
			if err := checkVerifyBoundToPlan(vsum.PlanSHA256, planPath); err != nil {
				return NewInputError(err.Error())
			}
			vres := vsum.Results

			opts := acls.Options{
				RunDir:           runDir,
				PlanPath:         planPath,
				VerifyPath:       verifyPath,
				ACLsPath:         aclsPath,
				Verify:           vres,
				Principals:       principals,
				BootstrapServers: kaf.BootstrapServer,
				CommandConfig:    kaf.CommandConfig,
			}
			return acls.Generate(opts)
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to plan.json")
	cmd.Flags().StringVar(&verifyPath, "verify", "", "Path to verify.json")
	cmd.Flags().StringSliceVar(&principals, "principal", nil, "Principal filter (repeatable; alias: --principal-filter)")
	cmd.Flags().StringSliceVar(&principalFilter, "principal-filter", nil, "Alias for --principal (same semantics; matches extract / mds list-bindings)")
	cmd.Flags().StringVar(&principalFile, "principal-file", "", "Path to a file with one principal per line (alternative or supplement to --principal)")
	cmd.Flags().BoolVar(&confirmFlag, "confirm", false, "Confirm the operation")
	cmd.Flags().BoolVar(&understandDestr, "i-understand-this-is-destructive", false, "Required acknowledgement")
	kaf.AddKafkaAuthFlags(cmd)
	rdf.AddRunDirFlags(cmd)
	return cmd
}

func newDeleteDenyACLsCmd() *cobra.Command {
	var (
		planPath        string
		verifyPath      string
		principals      []string
		principalFilter []string
		principalFile   string
		mayGrantAccess  bool
		confirmFlag     bool
	)
	var mdsAuth MDSAuthFlags
	var kaf KafkaAuthFlags
	var rdf RunDirFlags

	cmd := &cobra.Command{
		Use:   "delete-deny-acls",
		Short: "Generate the DENY-ACL deletion script",
		Long: `Remove DENY ACLs that 'apply' converted, after 'verify' has confirmed
the corresponding bindings are EFFECTIVE_OK. Highly destructive — DENY ACLs
are safety-net rules; removing one without confirming the access shouldn't
flow through it can grant access to a principal that previously had none.

Emits a 'delete-deny-acls.sh' script in the run directory. The script does
NOT contain bare 'kafka-acls --remove' calls; instead each line invokes
'monedula-acl-rbac delete-deny-one' which re-checks effective permission at
script-execution time, per-ACL. The script is safe to inspect, reorder,
or partially run by hand.

Guardrails (all enforced):
  - 'verify' must be present (--verify)
  - --principal (or --principal-file) is REQUIRED — no untargeted sweep
  - wildcard-principal DENYs ('Deny User:* ...', bare '*', any '<Type>:*')
    are classified UNKNOWN (unbounded blast radius) and CANNOT be removed by
    this tool — remove them manually with kafka-acls if you are certain
  - --confirm AND --i-understand-this-may-grant-access required either way
  - DENY analysis must classify each ACL as SAFE_TO_REMOVE in plan.json

Unlike apply/verify, this command does NOT accept cache-only auth: pass
--mds-token-file, or --mds-user + --mds-password-file. The credentials are
baked into runtime.env so the generated script's delete-deny-one calls can
authenticate non-interactively at execution time, when a cached token may
have expired.

Example:
  monedula-acl-rbac delete-deny-acls \
    --plan runs/.../plan.json --verify runs/.../verify.json \
    --bootstrap-server kafka.example.com:9093 \
    --command-config admin.properties \
    --mds-url https://mds.example.com \
    --mds-token-file ~/.confluent/token \
    --principal User:alice \
    --confirm --i-understand-this-may-grant-access

Outputs: delete-deny-acls.sh, rollback-deny.sh, deleted-deny-acls.json,
delete-deny.log, runtime.env (0o600, removed on script exit).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if planPath == "" || verifyPath == "" {
				return NewUsageError("--plan and --verify are required")
			}
			if !mayGrantAccess {
				return NewUsageError("--i-understand-this-may-grant-access is required")
			}
			principals = mergePrincipals(principals, principalFilter)
			if principalFile != "" {
				filePrincipals, perr := parsePrincipalFile(principalFile)
				if perr != nil {
					return NewInputError(perr.Error())
				}
				principals = mergePrincipals(principals, filePrincipals)
			}
			if len(principals) == 0 {
				return NewUsageError("--principal (or --principal-file) is required (no untargeted sweep)")
			}
			if !confirmFlag {
				ok, err := Confirm(ConfirmInput{
					IsTTY:   StdinIsTTY(),
					Stdin:   os.Stdin,
					Summary: fmt.Sprintf("Generate DENY-deletion script from %s", planPath),
				})
				if err != nil {
					return err
				}
				if !ok {
					return NewUsageError("not confirmed")
				}
			}
			runDir, err := rdf.Resolve(planPath)
			if err != nil {
				return err
			}
			aclsPath := filepath.Join(runDir, "acls.json")
			vsum, err := readVerifySummary(verifyPath)
			if err != nil {
				return NewInputError(err.Error())
			}
			if err := checkVerifyBoundToPlan(vsum.PlanSHA256, planPath); err != nil {
				return NewInputError(err.Error())
			}
			vres := vsum.Results

			opts := deny.Options{
				RunDir:             runDir,
				PlanPath:           planPath,
				VerifyPath:         verifyPath,
				ACLsPath:           aclsPath,
				Verify:             vres,
				Principals:         principals,
				BootstrapServers:   kaf.BootstrapServer,
				CommandConfig:      kaf.CommandConfig,
				MDSURL:             mdsAuth.URL,
				MDSUser:            mdsAuth.User,
				MDSPasswordFile:    mdsAuth.PasswordFile,
				MDSTokenFile:       mdsAuth.TokenFile,
				MDSCACert:          mdsAuth.CACertPath,
				MDSClientCert:      mdsAuth.ClientCertPath,
				MDSClientKey:       mdsAuth.ClientKeyPath,
				InsecureSkipVerify: mdsAuth.InsecureSkipVerify,
				MaxRetries:         mdsAuth.MaxRetries,
			}
			return deny.Generate(opts)
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to plan.json")
	cmd.Flags().StringVar(&verifyPath, "verify", "", "Path to verify.json")
	cmd.Flags().StringSliceVar(&principals, "principal", nil, "Principal filter (REQUIRED; repeatable; alias: --principal-filter)")
	cmd.Flags().StringSliceVar(&principalFilter, "principal-filter", nil, "Alias for --principal (same semantics; matches extract / mds list-bindings)")
	cmd.Flags().StringVar(&principalFile, "principal-file", "", "Path to a file with one principal per line (alternative or supplement to --principal)")
	cmd.Flags().BoolVar(&mayGrantAccess, "i-understand-this-may-grant-access", false, "Required acknowledgement")
	cmd.Flags().BoolVar(&confirmFlag, "confirm", false, "Confirm the operation")
	mdsAuth.AddMDSAuthFlags(cmd)
	kaf.AddKafkaAuthFlags(cmd)
	rdf.AddRunDirFlags(cmd)
	return cmd
}

func newDeleteDenyOneCmd() *cobra.Command {
	var (
		runDir string
		aclID  int
	)
	cmd := &cobra.Command{
		Use: "delete-deny-one",
		Short: "Internal: per-ACL DENY removal with a live effective-permission re-check, " +
			"invoked by the generated delete-deny-acls.sh (not a user-facing command)",
		// Hidden from --help, completion, and the command list: this is an
		// implementation detail of delete-deny-acls.sh, not a command operators
		// run by hand. It must remain a registered subcommand because the
		// generated script re-invokes the binary as `monedula-acl-rbac
		// delete-deny-one` once per ACL to perform the live re-check; the
		// run-dir RUNTIME_AUTH_TOKEN handshake (and the checksum / rejected[] /
		// SAFE_TO_REMOVE / wildcard gates) still apply on every invocation.
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			envToken := os.Getenv("RUNTIME_AUTH_TOKEN")
			return deny.RunOne(deny.OneOptions{
				RunDir:   runDir,
				ACLID:    aclID,
				EnvToken: envToken,
			})
		},
	}
	cmd.Flags().StringVar(&runDir, "run-dir", "", "Run directory (required)")
	cmd.Flags().IntVar(&aclID, "acl-id", 0, "ACL ID to delete (required)")
	return cmd
}

// readVerify parses verify.json (envelope shape: {results, counts}).
// Bare arrays (any earlier dev-build form) are rejected — re-run
// 'verify' to regenerate.
func readVerify(path string) ([]verify.Result, error) {
	sum, err := readVerifySummary(path)
	if err != nil {
		return nil, err
	}
	return sum.Results, nil
}

// readVerifySummary parses verify.json into the full Summary envelope so
// callers can also inspect the stamped plan_sha256. Bare arrays (any
// earlier dev-build form) are rejected — re-run 'verify' to regenerate.
func readVerifySummary(path string) (verify.Summary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return verify.Summary{}, err
	}
	var sum verify.Summary
	if err := json.Unmarshal(data, &sum); err != nil {
		return verify.Summary{}, fmt.Errorf("parse verify.json: %w", err)
	}
	if sum.Results == nil {
		return verify.Summary{}, fmt.Errorf("verify.json missing top-level 'results' field; re-run 'verify' to regenerate (bare-array shape is no longer accepted)")
	}
	return sum, nil
}

// checkVerifyBoundToPlan refuses a verify.json generated against a
// different plan than the one being deleted against. verify stamps the
// plan's SHA-256 into verify.json (plan_sha256); here we re-hash the
// plan being deleted and compare. Closes the window where a stale
// verify.json from an earlier plan vouches for a re-generated plan.
func checkVerifyBoundToPlan(verifyPlanSHA, planPath string) error {
	if verifyPlanSHA == "" {
		return fmt.Errorf("verify.json is missing plan_sha256; re-run 'verify' against the current plan to regenerate it")
	}
	planSHA, err := common.FileSHA256(planPath)
	if err != nil {
		return err
	}
	if verifyPlanSHA != planSHA {
		return fmt.Errorf("verify.json was generated against a different plan (verify.PlanSHA256=%s, plan.sha256=%s); re-run 'verify' against the current plan", verifyPlanSHA, planSHA)
	}
	return nil
}
