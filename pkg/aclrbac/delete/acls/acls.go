// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package acls implements `delete-acls` per spec §4.3. The command emits
// a 'kafka-acls --remove' bash script in the run directory plus a
// symmetric rollback.sh; operators inspect, then run them by hand. The
// tool itself never executes destructive Kafka calls — that line is
// drawn deliberately so every deletion has a reviewable artifact.
package acls

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

// Options bundles inputs. The CLI in M8 fills these in from flags.
type Options struct {
	RunDir           string
	PlanPath         string
	VerifyPath       string // path to verify.json on disk; SHA-256'd into script header per spec §4.3
	ACLsPath         string
	Verify           []verify.Result
	Principals       []string
	BootstrapServers string
	CommandConfig    string
}

// Generate writes delete-acls.sh, rollback.sh, and deleted-acls.json into
// the run directory. It does NOT execute deletions. Spec §4.3 default.
func Generate(opts Options) error {
	// Validate runtime credentials up front (parity with delete-deny-acls,
	// see deny.validateRuntimeCredentials). The generated script invokes
	// `kafka-acls --remove --bootstrap-server <X>`; without a bootstrap
	// server runtime.env / the script is written with --bootstrap-server ""
	// and the failure is deferred to `bash delete-acls.sh` time, long after
	// the run-directory artefacts are committed. delete-acls (unlike
	// delete-deny-acls) does NOT touch MDS, so no MDS URL/auth is required;
	// --command-config is optional since most production setups supply SASL
	// via flags or the environment.
	if err := validateRuntimeCredentials(opts); err != nil {
		return err
	}
	// Make sure the run directory exists before any artefact write. plan
	// and extract both call rundir.Ensure up-front; delete-acls previously
	// assumed it; running with a non-existent --run-dir produced an
	// opaque "open .../deleted-acls.json: no such file or directory".
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
	// Integrity: the deletion argv is selected from acls.json by row id, so a
	// regenerated/edited acls.json could feed kafka-acls a different ACL than
	// the plan analyzed. Refuse when the file no longer matches the SHA the
	// plan was stamped with at plan time.
	if err := common.VerifyACLsSHA(plan.AclsSHA256, opts.ACLsPath); err != nil {
		return err
	}

	eligible := common.EligibleACLs(common.EligibilityInputs{
		Plan:       plan,
		Verify:     opts.Verify,
		Principals: opts.Principals,
	})
	if len(eligible) == 0 {
		return fmt.Errorf("no ACLs eligible for deletion (check verify results, --principal)")
	}

	rows := pickRows(acls.ACLs, eligible)

	// Write deleted-acls.json BEFORE the script (spec §4.3 pre-flight).
	deletedData, _ := json.MarshalIndent(rows, "", "  ")
	if err := rundir.WriteAtomic(filepath.Join(opts.RunDir, "deleted-acls.json"), deletedData, 0o600); err != nil {
		return err
	}

	// Write the deletion script.
	if err := writeScript(opts, rows, filepath.Join(opts.RunDir, "delete-acls.sh")); err != nil {
		return err
	}

	// Write the rollback script.
	if err := writeRollback(opts, rows, filepath.Join(opts.RunDir, "rollback.sh")); err != nil {
		return err
	}

	return nil
}

// validateRuntimeCredentials enforces that the operator supplied enough
// Kafka connectivity at script-generation time for the downstream
// `kafka-acls --remove` invocations to work. Mirrors
// deny.validateRuntimeCredentials but with the narrower delete-acls
// surface: a bootstrap server is required; --command-config is optional;
// no MDS URL/auth is needed since delete-acls never contacts MDS.
func validateRuntimeCredentials(opts Options) error {
	if strings.TrimSpace(opts.BootstrapServers) == "" {
		return fmt.Errorf("delete-acls: --bootstrap-server is required (used by the generated `kafka-acls --remove` invocations)")
	}
	return nil
}

func pickRows(all []types.ACLRow, ids []int) []types.ACLRow {
	id := map[int]bool{}
	for _, x := range ids {
		id[x] = true
	}
	var out []types.ACLRow
	for _, r := range all {
		if id[r.ID] {
			out = append(out, r)
		}
	}
	return out
}
