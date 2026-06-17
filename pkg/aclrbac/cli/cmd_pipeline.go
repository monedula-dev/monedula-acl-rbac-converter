// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/apply"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit"
	emitcfk "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/cfk"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/mdscurl"
	emitscript "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/script"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/log"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/report"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

func newPlanCmd() *cobra.Command {
	var (
		aclsPath       string
		rulesPath      string
		principalsPath string
		scopesPath     string
		allowUnmapped  bool
		allowRejected  bool
		revalidatePath string
		cfkNameSalt    string
	)
	var rdf RunDirFlags

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Transform acls.json into plan.json + report.txt",
		Long: `Apply the mapping engine to acls.json and emit a RoleBindingPlan in
plan.json plus a human-readable report.txt next to it.

Required:
  --acls    path to canonical acls.json from 'extract'
  --scopes  scopes.yaml identifying the Confluent cluster IDs to bind into

Optional:
  --rules        custom rules.yaml merged on top of the embedded defaults
  --principals   principals.yaml mapping source ACL principals to MDS forms
  --allow-unmapped    proceed even if some ACLs had no rule (exit 0 instead of 3)
  --allow-rejected    proceed even if some ACLs are DENY or otherwise unrepresentable
  --revalidate PLAN   re-checksum a hand-edited plan.json after operator edits

Example:
  monedula-acl-rbac plan \
    --acls runs/.../acls.json --scopes scopes.yaml \
    --rules rules.yaml --principals principals.yaml \
    --out runs/.../plan.json

plan exits non-zero (code 3) when unmapped or rejected ACLs are present
unless the corresponding --allow-* flag is set. Read report.txt before
moving to 'apply'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Revalidate mode is a separate code path.
			if revalidatePath != "" {
				p, err := rundir.ReadPlan(revalidatePath)
				if err != nil {
					return NewInputError(err.Error())
				}
				if _, err := plan.Revalidate(p); err != nil {
					return NewInputError(err.Error())
				}
				if err := rundir.WriteChecksum(revalidatePath); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "revalidated %s\n", revalidatePath)
				return nil
			}

			if aclsPath == "" {
				return NewUsageError("--acls is required")
			}
			if scopesPath == "" {
				return NewUsageError("--scopes is required")
			}

			outPath := rdf.Out
			if outPath == "" {
				dir, err := rdf.Resolve(aclsPath)
				if err != nil {
					return err
				}
				outPath = filepath.Join(dir, "plan.json")
			}

			acls, err := rundir.ReadACLs(aclsPath)
			if err != nil {
				return NewInputError(err.Error())
			}
			scopeData, err := os.ReadFile(scopesPath)
			if err != nil {
				return NewInputError(err.Error())
			}
			scope, err := config.ParseScopes(scopeData)
			if err != nil {
				return NewInputError(err.Error())
			}
			defaults, _ := config.DefaultRulesYAML()
			rules, err := config.ParseRules(defaults)
			if err != nil {
				return err
			}
			if rulesPath != "" {
				ovData, err := os.ReadFile(rulesPath)
				if err != nil {
					return NewInputError(err.Error())
				}
				overrides, err := config.ParseRules(ovData)
				if err != nil {
					return NewInputError(err.Error())
				}
				rules = config.MergeRules(rules, overrides)
			}
			var principals config.Principals
			if principalsPath != "" {
				pdata, err := os.ReadFile(principalsPath)
				if err != nil {
					return NewInputError(err.Error())
				}
				principals, err = config.ParsePrincipals(pdata)
				if err != nil {
					return NewInputError(err.Error())
				}
			} else {
				principals = config.Principals{Fallback: config.PrincipalFallbackPassThrough}
			}

			// existing-bindings.json is written by CFK / K8s extractors next
			// to acls.json. When present, the planner uses it to mark
			// already-applied role bindings as SKIP_EXISTS instead of CREATE.
			existingBindings, err := readExistingBindings(filepath.Dir(aclsPath))
			if err != nil {
				return NewInputError(err.Error())
			}

			p, err := plan.Run(plan.Input{
				ACLs:             acls,
				Rules:            rules,
				Principals:       principals,
				Scopes:           scope,
				ExistingBindings: existingBindings,
				CFKNameSalt:      cfkNameSalt,
			})
			if err != nil {
				return err
			}

			// Stamp the acls.json SHA-256 into the plan so the destructive
			// delete commands can refuse a regenerated/edited acls.json that no
			// longer matches what was analyzed (the kafka-acls argv is selected
			// from acls.json by row id at delete time).
			if sum, herr := common.FileSHA256(aclsPath); herr == nil {
				p.AclsSHA256 = sum
			} else {
				return NewInputError(herr.Error())
			}

			if err := rundir.WritePlan(outPath, p); err != nil {
				return err
			}
			if err := rundir.WriteChecksum(outPath); err != nil {
				return err
			}

			reportPath := filepath.Join(filepath.Dir(outPath), "report.txt")
			// 0o600: report.txt summarises every ACL → binding decision,
			// including principal names and resource patterns. Match
			// the rest of the run-directory artefacts (plan.json,
			// acls.json, verify.json) which are also 0o600.
			rf, err := os.OpenFile(reportPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer rf.Close()
			if err := report.Render(rf, p, report.FormatText); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr, report.Summary(p))

			if !allowUnmapped && len(p.Unmapped) > 0 {
				return NewPlanError(fmt.Sprintf("%d unmapped ACL group(s); pass --allow-unmapped to proceed", len(p.Unmapped)))
			}
			if !allowRejected && len(p.Rejected) > 0 {
				return NewPlanError(fmt.Sprintf("%d rejected ACL group(s); pass --allow-rejected to proceed", len(p.Rejected)))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&aclsPath, "acls", "", "Path to acls.json")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "Optional rules.yaml overrides")
	cmd.Flags().StringVar(&principalsPath, "principals", "", "Optional principals.yaml")
	cmd.Flags().StringVar(&scopesPath, "scopes", "", "scopes.yaml")
	cmd.Flags().BoolVar(&allowUnmapped, "allow-unmapped", false, "Don't fail on unmapped ACLs")
	cmd.Flags().BoolVar(&allowRejected, "allow-rejected", false, "Don't fail on rejected (DENY) ACLs")
	cmd.Flags().BoolVar(&allowRejected, "allow-deny-drop", false, "Deprecated: use --allow-rejected")
	_ = cmd.Flags().MarkDeprecated("allow-deny-drop", "use --allow-rejected instead")
	cmd.Flags().StringVar(&revalidatePath, "revalidate", "", "Re-checksum a hand-edited plan.json")
	cmd.Flags().StringVar(&cfkNameSalt, "cfk-name-salt", "", "Salt mixed into binding IDs; lets you disambiguate identical bindings across tenants")
	rdf.AddRunDirFlags(cmd)
	return cmd
}

func newReportCmd() *cobra.Command {
	var (
		planPath string
		format   string
		outPath  string
		strict   bool
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-print plan.json's report in alternate formats",
		Long: `Render the report embedded in plan.json (text, markdown, or json).

By default exits 0 on successful render, regardless of whether the
plan contains UNMAPPED or REJECTED bindings — viewing a plan should
not fail. Pass --strict to make the command exit with a plan-error
code when the plan is unhealthy (useful in CI scripts that gate the
next step on a clean report).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if planPath == "" {
				return NewUsageError("--plan is required")
			}
			p, err := rundir.ReadPlan(planPath)
			if err != nil {
				return NewInputError(err.Error())
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
			f := report.Format(format)
			if format == "" {
				f = report.FormatText
			}
			if err := report.Render(w, p, f); err != nil {
				return err
			}
			if strict && (len(p.Unmapped) > 0 || len(p.Rejected) > 0) {
				return NewPlanError("plan has unresolved unmapped/rejected items")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to plan.json")
	cmd.Flags().StringVar(&format, "format", "text", "text|markdown|json")
	cmd.Flags().StringVar(&outPath, "out", "", "Output path (default: stdout)")
	cmd.Flags().BoolVar(&strict, "strict", false, "Exit non-zero when the plan has UNMAPPED or REJECTED items (default: render and exit 0)")
	return cmd
}

func newEmitCmd() *cobra.Command {
	var (
		planPath     string
		format       string
		outPath      string
		cfkNamespace string
		cfkNameSalt  string
	)
	cmd := &cobra.Command{
		Use:   "emit",
		Short: "Render plan.json as an external artifact",
		RunE: func(cmd *cobra.Command, args []string) error {
			if planPath == "" {
				return NewUsageError("--plan is required")
			}
			p, err := rundir.ReadPlan(planPath)
			if err != nil {
				return NewInputError(err.Error())
			}

			var w io.Writer = os.Stdout
			if outPath != "" {
				// Determine output file based on format.
				ext := map[string]string{"script": "script.sh", "cfk": "cfk.yaml", "mds-curl": "mds-curl.sh"}[format]
				if ext == "" {
					ext = "out.txt"
				}
				if err := os.MkdirAll(outPath, 0o755); err != nil {
					return err
				}
				f, err := os.Create(filepath.Join(outPath, ext))
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}

			var em emit.Emitter
			switch format {
			case "", "script":
				em = emitscript.New(emitscript.Options{PlanPath: planPath})
			case "cfk":
				em = emitcfk.New(emitcfk.Options{Namespace: cfkNamespace})
			case "mds-curl":
				em = mdscurl.New(mdscurl.Options{PlanPath: planPath})
			default:
				return NewUsageError("--format " + format + " is not recognized")
			}
			if cfkNameSalt != "" {
				log.Warn("--cfk-name-salt on `emit` is deprecated and has no effect; pass it to `plan` instead so the salt is baked into binding IDs")
			}
			_, err = em.Emit(w, p)
			return err
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to plan.json")
	cmd.Flags().StringVar(&format, "format", "script", "script|cfk|mds-curl")
	cmd.Flags().StringVar(&outPath, "out-dir", "", "Output directory (default: stdout). emit writes one or more files; --out-dir is the directory those files land in.")
	cmd.Flags().StringVar(&cfkNamespace, "cfk-namespace", "", "CFK ConfluentRolebinding namespace")
	cmd.Flags().StringVar(&cfkNameSalt, "cfk-name-salt", "", "(Deprecated: use --cfk-name-salt on `plan` instead)")
	return cmd
}

func newApplyCmd() *cobra.Command {
	var (
		planPath     string
		dryRun       bool
		confirmFlag  bool
		parallelism  int
		forceUnlock  bool
		progressFlag bool
		format       string
	)
	var mdsAuth MDSAuthFlags
	var rdf RunDirFlags

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Create RBAC bindings in MDS from plan.json",
		Long: `Create the RBAC role bindings described in plan.json by calling MDS.
Idempotent: bindings already present in MDS are skipped. Concurrent
writers are blocked via a per-run-directory lockfile.

Mutating. Requires either --confirm on the command line or an
interactive 'yes' typed at the TTY prompt. Use --dry-run first to
preview the MDS calls without writing.

Output and behaviour flags worth knowing:
  --format text|json          structured summary on stdout
  --apply-parallelism N       concurrent MDS writes (default 4)
  --mds-max-retries N         retry transient failures (default 3; 0 disables)
  --progress                  per-binding progress on stderr (default: on when stderr is a TTY)

Auth (any one of):
  --mds-token-file FILE          pre-fetched bearer token
  --mds-user + --mds-password-file  exchange via /security/1.0/authenticate
  cached token from a prior 'auth login' (auto-discovered)

Example:
  monedula-acl-rbac apply \
    --plan runs/.../plan.json \
    --mds-url https://mds.example.com \
    --mds-token-file ~/.confluent/token \
    --confirm

Outputs: apply.log (every MDS call + result). --dry-run additionally
writes would-apply.log with the request bodies that would have been
sent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if planPath == "" {
				return NewUsageError("--plan is required")
			}
			if dryRun && confirmFlag {
				return NewUsageError("--dry-run and --confirm are mutually exclusive")
			}
			switch apply.Format(format) {
			case apply.FormatText, apply.FormatJSON:
				// ok
			default:
				return NewUsageError(fmt.Sprintf("--format %s not recognised (want text|json)", format))
			}

			runDir, err := rdf.Resolve(planPath)
			if err != nil {
				return err
			}

			cl, err := mdsAuth.ResolveClient()
			if err != nil {
				return err
			}

			if dryRun {
				return apply.DryRun(apply.Options{
					RunDir:        runDir,
					PlanPath:      planPath,
					Client:        cl,
					SummaryWriter: os.Stdout,
					SummaryFormat: apply.Format(format),
				})
			}

			if !confirmFlag {
				ok, err := Confirm(ConfirmInput{
					ConfirmFlag: confirmFlag,
					IsTTY:       StdinIsTTY(),
					Stdin:       os.Stdin,
					Summary:     fmt.Sprintf("Apply plan %s to MDS at %s", planPath, mdsAuth.URL),
				})
				if err != nil {
					return err
				}
				if !ok {
					return NewUsageError("not confirmed")
				}
			}

			return apply.Run(apply.Options{
				RunDir:        runDir,
				PlanPath:      planPath,
				Client:        cl,
				Parallelism:   parallelism,
				ForceUnlock:   forceUnlock,
				Progress:      apply.NewProgress(progressFlag),
				SummaryWriter: os.Stdout,
				SummaryFormat: apply.Format(format),
			})
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to plan.json")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview the MDS API calls without mutating")
	cmd.Flags().BoolVar(&confirmFlag, "confirm", false, "Confirm the mutation")
	cmd.Flags().IntVar(&parallelism, "apply-parallelism", 4, "Concurrent MDS writes")
	cmd.Flags().BoolVar(&forceUnlock, "force-unlock", false, "Clear a stale lockfile")
	cmd.Flags().BoolVar(&progressFlag, "progress", false, "Print per-binding progress to stderr (default: on when stderr is a TTY)")
	cmd.Flags().StringVar(&format, "format", "text", "Summary output format on stdout (text|json)")
	mdsAuth.AddMDSAuthFlags(cmd)
	rdf.AddRunDirFlags(cmd)
	return cmd
}

func newVerifyCmd() *cobra.Command {
	var (
		planPath     string
		mode         string
		parallelism  int
		acceptUnk    bool
		progressFlag bool
		format       string
	)
	var mdsAuth MDSAuthFlags
	var rdf RunDirFlags

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check effective access of each binding in MDS",
		Long: `Confirm that each binding created by 'apply' actually grants the
access the original ACL granted. Strongly recommended before
'delete-acls' — deletion is blocked unless verify reports EFFECTIVE_OK
for every source ACL.

Modes:
  --mode effective       (default) MDS effective-access lookup per source ACL
  --mode bindings-exist  smoke check that the binding row is present

Effective mode classifies each source ACL as:
  EFFECTIVE_OK       the binding grants the access it should
  EFFECTIVE_MISSING  the binding exists but the principal still can't act
  EFFECTIVE_UNKNOWN  MDS lookup endpoint unavailable or ambiguous

Example:
  monedula-acl-rbac verify \
    --plan runs/.../plan.json \
    --mds-url https://mds.example.com \
    --mds-token-file ~/.confluent/token

verify.json is written into the run directory next to plan.json.
Reads acls.json from the same directory to populate per-source-ACL
operation/resource maps required for effective mode.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if planPath == "" {
				return NewUsageError("--plan is required")
			}
			switch verify.Format(format) {
			case verify.FormatText, verify.FormatJSON:
				// ok
			default:
				return NewUsageError(fmt.Sprintf("--format %s not recognised (want text|json)", format))
			}
			runDir, err := rdf.Resolve(planPath)
			if err != nil {
				return err
			}
			cl, err := mdsAuth.ResolveClient()
			if err != nil {
				return err
			}
			vmode := verify.Mode(mode)
			if vmode == "" {
				vmode = verify.ModeEffective
			}

			var sourceOps map[int]types.Operation
			var sourceResources map[int]verify.ResourceRef
			if vmode == verify.ModeEffective {
				aclsFile := filepath.Join(runDir, "acls.json")
				aclSet, err := rundir.ReadACLs(aclsFile)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						return fmt.Errorf("verify --mode effective requires acls.json in the run directory (%s); run `monedula-acl-rbac extract --out %s/acls.json ...` first", runDir, runDir)
					}
					return fmt.Errorf("verify --mode effective: read acls.json: %w", err)
				}
				sourceOps = make(map[int]types.Operation, len(aclSet.ACLs))
				sourceResources = make(map[int]verify.ResourceRef, len(aclSet.ACLs))
				for _, row := range aclSet.ACLs {
					sourceOps[row.ID] = row.Operation
					sourceResources[row.ID] = verify.ResourceRef{
						Type:    row.ResourceType,
						Name:    row.ResourceName,
						Pattern: row.PatternType,
					}
				}
			}

			results, err := verify.Run(verify.Options{
				RunDir:          runDir,
				PlanPath:        planPath,
				Client:          cl,
				Mode:            vmode,
				Parallelism:     parallelism,
				AcceptUnknown:   acceptUnk,
				SourceOps:       sourceOps,
				SourceResources: sourceResources,
				Progress:        verify.NewProgress(progressFlag),
				OutPath:         rdf.Out,
				SummaryWriter:   os.Stdout,
				SummaryFormat:   verify.Format(format),
			})
			if err != nil {
				return err
			}
			// verify is the documented gate before `delete-acls`; the
			// generated script refuses to delete rows whose verify result
			// isn't EFFECTIVE_OK / BindingExists. Make that posture visible
			// in the exit code too — operators running `verify` in CI now
			// get a non-zero exit on any unhealthy result instead of having
			// to parse verify.json or wait for delete-acls to refuse.
			// AcceptUnknown is honoured upstream (verify.Run downgrades
			// UNKNOWN -> OK in `results` before returning), so the only way
			// UNKNOWN survives here is if the operator deliberately did NOT
			// accept it. verify.json is still written before this check, so
			// the operator can inspect details on a non-zero exit.
			missing, unknown := 0, 0
			for _, r := range results {
				switch r.Status {
				case verify.StatusEffectiveMissing, verify.StatusBindingMissing:
					missing++
				case verify.StatusEffectiveUnknown:
					unknown++
				}
			}
			if missing+unknown > 0 {
				return NewGuardrailError(fmt.Sprintf(
					"verify reports unhealthy state: %d missing, %d unknown (inspect verify.json; re-run with --accept-unknown-verify to treat UNKNOWN as OK)",
					missing, unknown))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "Path to plan.json")
	cmd.Flags().StringVar(&mode, "mode", "effective", "bindings-exist|effective")
	cmd.Flags().IntVar(&parallelism, "verify-parallelism", 8, "Concurrent MDS lookups")
	cmd.Flags().BoolVar(&acceptUnk, "accept-unknown-verify", false, "Treat EFFECTIVE_UNKNOWN as OK")
	cmd.Flags().BoolVar(&progressFlag, "progress", false, "Print per-binding progress to stderr (default: on when stderr is a TTY)")
	cmd.Flags().StringVar(&format, "format", "text", "Summary output format on stdout (text|json)")
	mdsAuth.AddMDSAuthFlags(cmd)
	rdf.AddRunDirFlags(cmd)
	return cmd
}

// readExistingBindings reads existing-bindings.json from the given run
// directory if it exists. Returns (nil, nil) when the file is absent —
// most run directories won't have one (only CFK / K8s sources produce
// it).
func readExistingBindings(runDir string) ([]types.Binding, error) {
	path := filepath.Join(runDir, "existing-bindings.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read existing-bindings.json: %w", err)
	}
	var bindings []types.Binding
	if err := json.Unmarshal(data, &bindings); err != nil {
		return nil, fmt.Errorf("parse existing-bindings.json: %w", err)
	}
	return bindings, nil
}
