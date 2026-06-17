// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package deny implements `delete-deny-acls` per spec §4.4. The command
// emits a bash script that loops the eligible DENY rows through the
// internal `delete-deny-one` helper (which performs the live SAFE_TO_REMOVE
// re-check against MDS at script-execution time, not generation time) and
// a symmetric rollback-deny.sh. The Go side never executes destructive
// Kafka calls — operators inspect the generated scripts and run them by
// hand; runtime.env carries the bootstrap-server + MDS credentials the
// scripts need.
//
// Wildcard-principal DENYs (`User:*`, bare `*`, any `<Type>:*`) are
// classified UNKNOWN by the eligibility analysis and are refused both at
// generation time and inside `delete-deny-one` — there is no
// confirmation-token override.
package deny

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/verify"
)

// Options bundles inputs for the orchestrator.
type Options struct {
	RunDir             string
	PlanPath           string
	VerifyPath         string // path to verify.json on disk; SHA-256'd into script header per spec §4.3
	ACLsPath           string
	Verify             []verify.Result
	Principals         []string // required (spec §4.4)
	BootstrapServers   string
	CommandConfig      string
	MDSURL             string
	MDSUser            string
	MDSPasswordFile    string
	MDSTokenFile       string
	MDSCACert          string
	MDSClientCert      string
	MDSClientKey       string
	InsecureSkipVerify bool
	MaxRetries         int
}

// Generate writes delete-deny-acls.sh + runtime.env + rollback-deny.sh +
// deleted-deny-acls.json. Does NOT execute deletions.
func Generate(opts Options) error {
	// Validate runtime credentials up front. The generated script invokes
	// `delete-deny-one` which needs MDS to perform the live SAFE_TO_REMOVE
	// re-check (spec §4.4) and `kafka-acls --remove` which needs the
	// bootstrap server. Without these, runtime.env is written with empty
	// values and the failure is deferred until script execution — well
	// after the operator's run-directory artefacts are committed. Fail
	// fast instead so the script is never generated in a state that
	// cannot succeed.
	if err := validateRuntimeCredentials(opts); err != nil {
		return err
	}
	// Make sure the run directory exists before any artefact write — see
	// the matching note on acls.Generate. Without this, a stray
	// --run-dir typo bubbles up as "open .../runtime.env: no such file
	// or directory" mid-way through artefact emission.
	if err := rundir.Ensure(opts.RunDir); err != nil {
		return err
	}
	if err := rundir.VerifyChecksum(opts.PlanPath); err != nil {
		return err
	}
	plan, err := rundir.ReadPlan(opts.PlanPath)
	if err != nil {
		return err
	}
	acls, err := rundir.ReadACLs(opts.ACLsPath)
	if err != nil {
		return err
	}
	// Integrity: the per-ACL kafka-acls argv is selected from acls.json by row
	// id, so refuse a regenerated/edited acls.json that no longer matches the
	// SHA the plan was stamped with.
	if err := common.VerifyACLsSHA(plan.AclsSHA256, opts.ACLsPath); err != nil {
		return err
	}

	if len(opts.Principals) == 0 {
		return fmt.Errorf("delete-deny-acls: --principal is required (spec §4.4: no untargeted sweep)")
	}

	// Honor the documented guardrail: removing the source DENY ACLs is only
	// safe once the RBAC replacement is confirmed live. verify.json is already
	// bound to this plan by SHA; here we also enforce that its statuses are
	// acceptable. Any non-OK row (EFFECTIVE_MISSING/UNKNOWN, BINDING_MISSING/
	// UNKNOWN) means the replacement isn't confirmed, so refuse. Operators who
	// accept unknowns can re-run verify with --accept-unknown-verify (which
	// downgrades UNKNOWN to OK in the results).
	if n := unconfirmedVerifyResults(opts.Verify); n > 0 {
		return fmt.Errorf("delete-deny-acls: %d verify result(s) are not EFFECTIVE_OK/BINDING_EXISTS; the RBAC replacement is not confirmed, so removing DENY ACLs is unsafe (re-run verify, or use --accept-unknown-verify if appropriate)", n)
	}

	rows, err := pickEligibleDeny(plan, acls, opts)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		// Spec §4.4: wildcard-principal DENYs are classified UNKNOWN by the
		// planner (their blast radius is unbounded — they cover principals the
		// analysis cannot enumerate), so they never reach SAFE_TO_REMOVE and
		// this tool refuses to remove them. There is no confirmation-token
		// escape hatch: an unbounded DENY removal is not something automation
		// should make easy. Give the operator a targeted reason rather than a
		// bare "nothing eligible".
		return fmt.Errorf("%s", noEligibleDenyReason(plan, acls, opts))
	}

	// Write runtime.env first (script will source it).
	authToken := common.NewAuthToken()
	if _, err := common.WriteRuntimeEnv(opts.RunDir, common.RuntimeEnv{
		BootstrapServers:   opts.BootstrapServers,
		CommandConfig:      opts.CommandConfig,
		MDSURL:             opts.MDSURL,
		MDSUser:            opts.MDSUser,
		MDSPasswordFile:    opts.MDSPasswordFile,
		MDSTokenFile:       opts.MDSTokenFile,
		MDSCACert:          opts.MDSCACert,
		MDSClientCert:      opts.MDSClientCert,
		MDSClientKey:       opts.MDSClientKey,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		MaxRetries:         opts.MaxRetries,
		AuthToken:          authToken,
	}); err != nil {
		return err
	}

	if err := writeDeletedDenyJSON(opts.RunDir, rows); err != nil {
		return err
	}
	if err := writeRollback(opts, rows, filepath.Join(opts.RunDir, "rollback-deny.sh")); err != nil {
		return err
	}

	return writeScript(opts, rows, filepath.Join(opts.RunDir, "delete-deny-acls.sh"))
}

// unconfirmedVerifyResults counts verify results that do not confirm a live
// binding (anything other than EFFECTIVE_OK / BINDING_EXISTS), mirroring the
// acceptability rule in delete/common/eligibility.go.
func unconfirmedVerifyResults(results []verify.Result) int {
	n := 0
	for _, r := range results {
		if r.Status != verify.StatusEffectiveOK && r.Status != verify.StatusBindingExists {
			n++
		}
	}
	return n
}

func pickEligibleDeny(plan types.Plan, acls types.ACLSet, opts Options) ([]types.ACLRow, error) {
	principalSet := map[string]bool{}
	for _, p := range opts.Principals {
		principalSet[p] = true
	}

	denyStatus := map[int]types.DenyAnalysisStatus{}
	for _, d := range plan.DenyAnalysis {
		denyStatus[d.SourceACLID] = d.Status
	}

	var out []types.ACLRow
	for _, r := range acls.ACLs {
		if r.PermissionType != types.PermissionDeny {
			continue
		}
		if !principalSet[r.Principal] {
			continue
		}
		// Defence in depth: never remove a wildcard-principal DENY, even if
		// plan.json claims SAFE_TO_REMOVE. Its blast radius is unbounded — it
		// covers principals the analysis cannot enumerate. The planner already
		// classifies these UNKNOWN, but we re-check here so a hand-edited or
		// buggy plan.json cannot sneak one through this last gate. Uses the
		// shared types.IsWildcardPrincipal so both sides agree on "wildcard".
		if types.IsWildcardPrincipal(r.Principal) {
			continue
		}
		// Spec §4.4: only DENY ACLs the planner rejected are removable. Skip
		// any row not in plan.json::rejected[] so we fail fast at generation
		// rather than emitting a script delete-deny-one would refuse per-ACL.
		if !aclInRejected(plan, r.ID) {
			continue
		}
		st := denyStatus[r.ID]
		if st == types.DenySafeToRemove {
			out = append(out, r)
		}
	}
	return out, nil
}

// noEligibleDenyReason explains why pickEligibleDeny returned nothing, so the
// operator isn't left guessing at a bare "nothing eligible". The common
// surprise is a wildcard-principal DENY: the planner classifies it UNKNOWN
// (unbounded blast radius), so it never reaches SAFE_TO_REMOVE and this tool
// refuses to remove it — with no token escape hatch. Uses the shared
// types.IsWildcardPrincipal so this stays consistent with the planner.
func noEligibleDenyReason(plan types.Plan, acls types.ACLSet, opts Options) string {
	principalSet := map[string]bool{}
	for _, p := range opts.Principals {
		principalSet[p] = true
	}

	var wildcards []string
	seen := map[string]bool{}
	matched := 0
	for _, r := range acls.ACLs {
		if r.PermissionType != types.PermissionDeny || !principalSet[r.Principal] {
			continue
		}
		matched++
		if types.IsWildcardPrincipal(r.Principal) && !seen[r.Principal] {
			seen[r.Principal] = true
			wildcards = append(wildcards, r.Principal)
		}
	}

	switch {
	case len(wildcards) > 0:
		return fmt.Sprintf("no DENY ACLs eligible for removal: wildcard-principal DENY(s) %v are classified UNKNOWN "+
			"(their blast radius is unbounded) and cannot be removed by this tool — remove them manually with kafka-acls "+
			"if you are certain (spec §4.4)", wildcards)
	case matched > 0:
		return "no DENY ACLs eligible for removal: matching DENY ACL(s) were classified WOULD_GRANT_ACCESS or UNKNOWN in " +
			"plan deny_analysis; only SAFE_TO_REMOVE rows are eligible"
	default:
		return "no DENY ACLs eligible for removal: no DENY ACL matched --principal (check plan deny_analysis and --principal)"
	}
}

func writeDeletedDenyJSON(runDir string, rows []types.ACLRow) error {
	data, _ := json.MarshalIndent(rows, "", "  ")
	return rundir.WriteAtomic(filepath.Join(runDir, "deleted-deny-acls.json"), data, 0o600)
}

// validateRuntimeCredentials enforces that the operator supplied enough
// MDS + Kafka credentials at script-generation time for the downstream
// `delete-deny-one` and `kafka-acls --remove` invocations to work. Without
// this check, runtime.env is written with empty values and the failure
// surfaces only when an operator (or CI/CD pipeline) executes the
// generated script — after the run directory is committed.
//
// Returned errors name the missing flag and what each is used for so the
// fix is actionable without consulting the spec.
func validateRuntimeCredentials(opts Options) error {
	// TrimSpace every field before the empty-check: a flag value of "  "
	// (e.g. from a shell variable that expanded to nothing) is just as
	// useless as "" but previously slipped past these guards, deferring
	// the failure to script-execution time. Whitespace-only credentials
	// also break the runtime.env shell-quoting downstream.
	if strings.TrimSpace(opts.MDSURL) == "" {
		return fmt.Errorf("delete-deny-acls: --mds-url is required (used by delete-deny-one for the live SAFE_TO_REMOVE re-check, spec §4.4)")
	}
	hasTokenFile := strings.TrimSpace(opts.MDSTokenFile) != ""
	hasUserPass := strings.TrimSpace(opts.MDSUser) != "" && strings.TrimSpace(opts.MDSPasswordFile) != ""
	if !hasTokenFile && !hasUserPass {
		return fmt.Errorf("delete-deny-acls: MDS authentication is required — pass --mds-token-file PATH, or --mds-user USER + --mds-password-file PATH (delete-deny-one performs a live MDS re-check before each ACL removal)")
	}
	if strings.TrimSpace(opts.BootstrapServers) == "" {
		return fmt.Errorf("delete-deny-acls: --bootstrap-server is required (used by the generated `kafka-acls --remove` invocations)")
	}
	return nil
}
