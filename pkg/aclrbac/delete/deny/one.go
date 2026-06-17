// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package deny

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// OneOptions feeds RunOne.
type OneOptions struct {
	RunDir        string
	ACLID         int
	EnvToken      string
	ExecKafkaACLs func(args []string) error
}

// RunOne performs the live re-check for one DENY ACL and either deletes it
// or records a SKIP/FAIL in delete-deny.log.
func RunOne(opts OneOptions) error {
	env, err := common.ReadRuntimeEnv(opts.RunDir)
	if err != nil {
		return err
	}
	// Constant-time compare so the per-run handshake token isn't probeable
	// via response timing. The empty-token guard stays: an empty
	// runtime.env token must always be a mismatch (ConstantTimeCompare of
	// two empty slices returns 1, which would otherwise let an empty
	// caller token pass).
	if env.AuthToken == "" || subtle.ConstantTimeCompare([]byte(env.AuthToken), []byte(opts.EnvToken)) != 1 {
		return fmt.Errorf("delete-deny-one: RUNTIME_AUTH_TOKEN mismatch (caller's value does not match runtime.env)")
	}

	// Spec §4.4: re-verify plan.json checksum before any MDS call.
	// Defends against tampering between `delete-deny-acls` script
	// generation and per-ACL execution. The DENY analysis the script
	// trusts lives in plan.json; if plan.json has changed since the
	// script was generated, every assumption downstream is invalid.
	planPath := filepath.Join(opts.RunDir, "plan.json")
	if err := rundir.VerifyChecksum(planPath); err != nil {
		return fmt.Errorf("delete-deny-one: plan.json checksum check failed: %w", err)
	}

	// B4: also confirm verify.json was generated against this exact plan.
	// verify stamps the plan's SHA-256 into verify.json; if it doesn't
	// match the run-dir plan.json, the SAFE_TO_REMOVE evidence the script
	// relies on came from a different plan and must not be trusted.
	if err := verifyBoundToPlan(filepath.Join(opts.RunDir, "verify.json"), planPath); err != nil {
		return fmt.Errorf("delete-deny-one: %w", err)
	}

	acls, err := rundir.ReadACLs(filepath.Join(opts.RunDir, "acls.json"))
	if err != nil {
		return err
	}
	row, ok := findRow(acls.ACLs, opts.ACLID)
	if !ok {
		return fmt.Errorf("delete-deny-one: acl_id=%d not present in acls.json", opts.ACLID)
	}
	if row.PermissionType != types.PermissionDeny {
		return fmt.Errorf("delete-deny-one: acl_id=%d is not a DENY ACL", opts.ACLID)
	}

	// Spec §4.4: wildcard-principal DENYs (bare "*", any "<Type>:*") are NEVER
	// removable by this tool — their blast radius is unbounded (they cover
	// principals the analysis cannot enumerate). The generator
	// (delete-deny-acls) already refuses to emit them, but delete-deny-one is
	// hidden yet still invocable (the generated script re-invokes it), so a
	// hand-edited and re-validated plan.json that marks a wildcard DENY
	// SAFE_TO_REMOVE must not be able to drive a removal through here. This re-check uses the shared
	// types.IsWildcardPrincipal so the generator and this last gate agree, and
	// it runs BEFORE the live MDS re-check (which, for a wildcard principal,
	// would find no grants and wrongly conclude "safe to remove").
	if types.IsWildcardPrincipal(row.Principal) {
		return fmt.Errorf("delete-deny-one: acl_id=%d has wildcard principal %q; wildcard-principal DENYs are classified UNKNOWN and are never removable by this tool (spec §4.4)", opts.ACLID, row.Principal)
	}

	// Spec §4.4: a direct invocation must target a DENY the planner
	// classified SAFE_TO_REMOVE. The generated script only emits safe rows,
	// but delete-deny-one is hidden yet still invocable — without this gate an
	// operator holding the per-run token could target a WOULD_GRANT_ACCESS or
	// UNKNOWN DENY the generator would never emit. The
	// live re-check below is defence-in-depth, not a substitute for the
	// planner's static classification.
	plan, err := rundir.ReadPlan(planPath)
	if err != nil {
		return fmt.Errorf("delete-deny-one: read plan.json for deny_analysis gate: %w", err)
	}
	// Integrity: acls.json was read above and the kafka-acls argv is built from
	// row.* — refuse if acls.json no longer matches the SHA the plan was
	// stamped with (a regenerated acls.json could reassign ids so a different
	// DENY sits at this acl-id).
	if err := common.VerifyACLsSHA(plan.AclsSHA256, filepath.Join(opts.RunDir, "acls.json")); err != nil {
		return fmt.Errorf("delete-deny-one: %w", err)
	}
	// Spec §4.4 (full contract): the acl-id must match an entry in
	// plan.json::rejected[] whose deny_analysis is SAFE_TO_REMOVE. Check
	// rejected[] membership first so a hand-edited plan can't drive a removal
	// off a fabricated deny_analysis entry alone.
	if !aclInRejected(plan, opts.ACLID) {
		return fmt.Errorf("delete-deny-one: acl_id=%d is not in plan.json::rejected[]; only DENY ACLs the planner rejected can be removed (spec §4.4)", opts.ACLID)
	}
	if status, found := denyStatusFor(plan, opts.ACLID); !found {
		return fmt.Errorf("delete-deny-one: acl_id=%d has no deny_analysis entry in plan.json; refusing", opts.ACLID)
	} else if status != types.DenySafeToRemove {
		return fmt.Errorf("delete-deny-one: acl_id=%d deny_analysis is %q, not SAFE_TO_REMOVE; refusing (spec §4.4)", opts.ACLID, status)
	}

	// Live re-check. Resolve MDS credentials from runtime.env: the
	// generator (delete-deny-acls) baked --mds-token-file or
	// --mds-user/--mds-password-file values into runtime.env so this
	// helper can authenticate without re-prompting. Without a Token
	// here every MDS call 401s, LookupAllowed returns an error, and
	// every ACL is logged as EFFECTIVE_UNKNOWN — defeating the live
	// re-check that's the architectural reason for delete-deny-one
	// (spec §4.4).
	tok, err := mds.ResolveToken(mds.AuthConfig{
		URL:                env.MDSURL,
		TokenFilePath:      env.MDSTokenFile,
		User:               env.MDSUser,
		PasswordFile:       env.MDSPasswordFile,
		CACertPath:         env.MDSCACert,
		ClientCertPath:     env.MDSClientCert,
		ClientKeyPath:      env.MDSClientKey,
		InsecureSkipVerify: env.InsecureSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("delete-deny-one: resolve MDS token from runtime.env: %w (was delete-deny-acls run with --mds-token-file or --mds-user + --mds-password-file?)", err)
	}
	cl, err := mds.NewClient(mds.Config{
		URL:                env.MDSURL,
		Token:              tok.Token,
		CACertPath:         env.MDSCACert,
		ClientCertPath:     env.MDSClientCert,
		ClientKeyPath:      env.MDSClientKey,
		InsecureSkipVerify: env.InsecureSkipVerify,
		MaxRetries:         env.MaxRetries,
	})
	if err != nil {
		return err
	}
	// DENY-removal safety uses OVERLAP semantics, not LookupAllowed's
	// coverage semantics: removing this DENY grants access iff the principal
	// holds ANY live grant whose resource set intersects the denied set —
	// including a LITERAL grant or a narrower PREFIXED grant INSIDE a
	// PREFIXED DENY. LookupAllowed would miss those (it requires the grant's
	// pattern to match the DENY's), which would wrongly remove the DENY.
	allowed, err := mds.PrincipalGrantOverlaps(cl, row.Principal, row.Operation, row.ResourceType, row.ResourceName, row.PatternType, planScope(plan))
	if err != nil {
		// Bail loudly on MDS auth errors: an expired token in
		// runtime.env would otherwise silently turn every ACL into
		// EFFECTIVE_UNKNOWN. The script's `set -e` will halt the
		// run on a non-zero exit, surfacing the problem after the
		// first failed ACL instead of after the entire (no-op) run.
		if mds.IsAuthError(err) {
			return fmt.Errorf("delete-deny-one: MDS authentication failed; runtime.env token may have expired or been revoked: %w", err)
		}
		return logSkip(opts.RunDir, opts.ACLID, "EFFECTIVE_UNKNOWN: live re-check failed: "+err.Error())
	}
	if allowed {
		return logSkip(opts.RunDir, opts.ACLID, "WOULD_GRANT_ACCESS: skipped per spec §4.4 (no override mechanism)")
	}

	// Build kafka-acls --remove argv.
	args := []string{
		"--bootstrap-server", env.BootstrapServers,
	}
	if env.CommandConfig != "" {
		args = append(args, "--command-config", env.CommandConfig)
	}
	args = append(args,
		"--remove", "--force",
		"--deny-principal", row.Principal,
		// kafka-acls delete filters match the host string exactly, and default
		// the filter host to "*" when omitted — so a host-restricted DENY would
		// match nothing and be falsely logged as removed. Always pass the
		// row's host so the filter targets the exact ACL.
		"--deny-host", row.Host,
		"--operation", string(row.Operation),
		"--resource-pattern-type", strings.ToLower(string(row.PatternType)),
	)
	switch row.ResourceType {
	case types.ResourceTopic:
		args = append(args, "--topic", row.ResourceName)
	case types.ResourceGroup:
		args = append(args, "--group", row.ResourceName)
	case types.ResourceCluster:
		args = append(args, "--cluster")
	case types.ResourceTransactionalID:
		args = append(args, "--transactional-id", row.ResourceName)
	case types.ResourceDelegationToken:
		args = append(args, "--delegation-token", row.ResourceName)
	}
	execFn := opts.ExecKafkaACLs
	if execFn == nil {
		execFn = realExec
	}
	if err := execFn(args); err != nil {
		return logFail(opts.RunDir, opts.ACLID, err.Error())
	}

	return logOK(opts.RunDir, opts.ACLID)
}

// verifyBoundToPlan refuses to proceed when verify.json was generated
// against a different plan than the run-dir plan.json. verify stamps the
// plan's SHA-256 into verify.json (plan_sha256); we re-hash plan.json
// (already checksum-validated by the caller) and compare.
func verifyBoundToPlan(verifyPath, planPath string) error {
	data, err := os.ReadFile(verifyPath)
	if err != nil {
		return fmt.Errorf("read verify.json: %w", err)
	}
	var sum struct {
		PlanSHA256 string `json:"plan_sha256"`
	}
	if err := json.Unmarshal(data, &sum); err != nil {
		return fmt.Errorf("parse verify.json: %w", err)
	}
	if sum.PlanSHA256 == "" {
		return fmt.Errorf("verify.json is missing plan_sha256; re-run 'verify' against the current plan to regenerate it")
	}
	planSHA, err := common.FileSHA256(planPath)
	if err != nil {
		return err
	}
	if sum.PlanSHA256 != planSHA {
		return fmt.Errorf("verify.json was generated against a different plan (verify.PlanSHA256=%s, plan.sha256=%s); re-run 'verify' against the current plan", sum.PlanSHA256, planSHA)
	}
	return nil
}

func findRow(rows []types.ACLRow, id int) (types.ACLRow, bool) {
	for _, r := range rows {
		if r.ID == id {
			return r, true
		}
	}
	return types.ACLRow{}, false
}

// denyStatusFor returns the planner's deny_analysis classification for the
// given source ACL id, and whether an entry was found.
// planScope returns a representative MDS lookup scope for the plan — the
// cluster(s) the migration targets, taken from the first binding's scope (all
// bindings in a plan share the same cluster scope). The live DENY re-check
// queries the principal's effective grants at this scope.
func planScope(plan types.Plan) types.Scope {
	for _, b := range plan.Bindings {
		return b.Scope
	}
	return types.Scope{}
}

func denyStatusFor(plan types.Plan, aclID int) (types.DenyAnalysisStatus, bool) {
	for _, e := range plan.DenyAnalysis {
		if e.SourceACLID == aclID {
			return e.Status, true
		}
	}
	return "", false
}

// aclInRejected reports whether aclID appears in any plan.json rejected[]
// entry. Spec §4.4 requires a removable DENY to be one the planner actually
// rejected (DENY ACLs always land in rejected[]). Re-checking membership here
// — not just trusting the deny_analysis entry — guards against a hand-edited
// plan.json that fabricates a SAFE_TO_REMOVE deny_analysis entry for an
// acl-id the planner never rejected.
func aclInRejected(plan types.Plan, aclID int) bool {
	for _, r := range plan.Rejected {
		for _, id := range r.SourceACLIDs {
			if id == aclID {
				return true
			}
		}
	}
	return false
}

// realExec shells out to kafka-acls. The binary defaults to "kafka-acls"
// (resolved on PATH) but can be overridden via MONEDULA_KAFKA_ACLS_BIN —
// useful when the tool ships as "kafka-acls.sh", lives off PATH, or needs
// to be pointed at a wrapper. It is also the seam the realExec-path test
// uses to verify the actual argv kafka-acls receives.
func realExec(args []string) error {
	bin := os.Getenv("MONEDULA_KAFKA_ACLS_BIN")
	if strings.TrimSpace(bin) == "" {
		bin = "kafka-acls"
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func logOK(runDir string, id int) error {
	return appendDenyLog(runDir, fmt.Sprintf("OK acl_id=%d", id))
}
func logSkip(runDir string, id int, msg string) error {
	return appendDenyLog(runDir, fmt.Sprintf("SKIP acl_id=%d %s", id, msg))
}
func logFail(runDir string, id int, msg string) error {
	if err := appendDenyLog(runDir, fmt.Sprintf("FAIL acl_id=%d %s", id, msg)); err != nil {
		return err
	}
	return fmt.Errorf("delete-deny-one: acl_id=%d FAIL: %s", id, msg)
}

func appendDenyLog(runDir, line string) error {
	f, err := os.OpenFile(filepath.Join(runDir, "delete-deny.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}
