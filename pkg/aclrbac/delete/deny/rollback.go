// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package deny

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

func writeRollback(opts Options, rows []types.ACLRow, dest string) error {
	abs, _ := filepath.Abs(opts.RunDir)

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
		ToolVersion:      version.Version + " (deny rollback)",
		GeneratedAt:      time.Now().UTC(),
		PlanSHA256:       planSHA,
		VerifySHA256:     verifySHA,
		BootstrapServers: opts.BootstrapServers,
		CommandConfig:    opts.CommandConfig,
		Principals:       opts.Principals,
		RunDir:           abs,
	}))

	for _, r := range rows {
		args := []string{"kafka-acls", "--bootstrap-server", opts.BootstrapServers}
		if opts.CommandConfig != "" {
			args = append(args, "--command-config", opts.CommandConfig)
		}
		args = append(args,
			"--add",
			"--deny-principal", r.Principal,
			// Re-add the DENY with its original host. Omitting --deny-host
			// defaults to "*", which would restore a strictly BROADER DENY
			// (all hosts) than ever existed — an access outage on rollback.
			"--deny-host", r.Host,
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

		// See note in delete/acls/script.go: Quote everything except the binary.
		// The previous `HasPrefix(a, "--")` exemption was a shell-injection
		// vector for any operator-supplied value starting with "--".
		quoted := make([]string, 0, len(args))
		for i, a := range args {
			if i == 0 {
				quoted = append(quoted, a)
				continue
			}
			quoted = append(quoted, shell.Quote(a))
		}
		fmt.Fprintln(&b, strings.Join(quoted, " "))
	}
	// 0o700: see note in script.go. Same destructive surface.
	if err := rundir.WriteAtomic(dest, []byte(b.String()), 0o700); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}
