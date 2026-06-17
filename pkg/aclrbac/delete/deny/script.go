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

	envPath := filepath.Join(abs, "runtime.env")
	qEnvPath := shell.Quote(envPath)

	// Build the early-exit cleanup block (armed before the integrity guard so
	// every exit path removes the runtime.env auth-token file).
	//
	// IMPORTANT — quoting: we assign the runtime.env path to a shell variable
	// and reference it inside the trap as "$__MONEDULA_RUNTIME_ENV" (double-
	// quoted expansion, safe across spaces and shell-meta). Embedding the
	// shell.Quote'd path directly inside the outer `trap '...'` single quotes
	// would split on any space in the run dir (the outer ' closes early on
	// `'/path/with space/...'`), aborting the script before cleanup is armed
	// and leaving the auth-token file behind.
	// `rc=$?` MUST be the first statement in the trap. Bash sets `$?` to the
	// exit status of the command that triggered EXIT, but every command run
	// inside the trap (e.g. `rm -f ...`) overwrites `$?` before we read it.
	// Capturing into `rc` immediately preserves the real exit code so the
	// printf reports it accurately (otherwise failures usually log "exit 0",
	// the success status of `rm -f`).
	earlyExitSetup := "__MONEDULA_RUNTIME_ENV=" + qEnvPath + "\n" +
		`trap 'rc=$?; rm -f "$__MONEDULA_RUNTIME_ENV"; printf "delete-deny-acls.sh complete (exit %d)\n" "$rc" >&2' EXIT`

	var b strings.Builder
	b.WriteString(common.BuildScriptHeader(common.HeaderInputs{
		ToolVersion:      version.Version,
		GeneratedAt:      time.Now().UTC(),
		PlanSHA256:       planSHA,
		VerifySHA256:     verifySHA,
		BootstrapServers: opts.BootstrapServers,
		CommandConfig:    opts.CommandConfig,
		MDSURL:           opts.MDSURL,
		Principals:       opts.Principals,
		RunDir:           abs,
		EarlyExitSetup:   earlyExitSetup,
	}))

	b.WriteString("# Source the runtime environment (must exist and be mode 0600).\n")
	// Quote every interpolation of the run-dir path consistently (see the
	// mdscurl shell-escaping fix). The run-dir path is operator-controlled
	// and may contain spaces or shell metacharacters; an unquoted echo
	// argument would word-split or glob-expand it.
	b.WriteString(`if [[ ! -f ` + qEnvPath + ` ]]; then echo "runtime.env missing at "` + qEnvPath + ` >&2; exit 5; fi` + "\n")
	// Spec §4.4 preflight: refuse to source runtime.env unless it is mode
	// 0600 — it holds the per-run RUNTIME_AUTH_TOKEN, so a group/world-
	// readable file would leak the handshake. `stat` differs between
	// coreutils (-c '%a') and BSD/macOS (-f '%Lp'); if neither form works we
	// skip the check rather than abort a legitimate run on an exotic host.
	b.WriteString(`__rtperms="$(stat -c '%a' ` + qEnvPath + ` 2>/dev/null || stat -f '%Lp' ` + qEnvPath + ` 2>/dev/null || echo "")"` + "\n")
	b.WriteString(`if [[ -n "$__rtperms" && "$__rtperms" != "600" ]]; then echo "runtime.env mode $__rtperms is not 0600 (it holds the auth token); refusing: "` + qEnvPath + ` >&2; exit 5; fi` + "\n")
	b.WriteString("# shellcheck source=/dev/null\n")
	b.WriteString("source " + qEnvPath + "\n")
	// delete-deny-one reads RUNTIME_AUTH_TOKEN from its *environment*
	// (os.Getenv). `source` sets it as a shell variable but does NOT export
	// it, so the `monedula-acl-rbac delete-deny-one` child below would see an
	// empty token and fail the handshake — aborting the whole run under
	// `set -e`. Export it so the child inherits it. (The MDS_* values are
	// re-read from the runtime.env file by delete-deny-one, so only the
	// token needs to cross the process boundary via the environment.)
	b.WriteString("export RUNTIME_AUTH_TOKEN\n\n")

	// The runtime.env-removal trap is armed at the top of the script (via
	// HeaderInputs.EarlyCleanupTrap), before the integrity guard, so it also
	// fires on an early guard exit. No second trap is needed here.

	for _, r := range rows {
		fmt.Fprintf(&b, "monedula-acl-rbac delete-deny-one --run-dir %s --acl-id %d\n",
			shell.Quote(abs), r.ID)
	}

	// 0o700: executable for owner only. DENY-deletion is the most
	// safety-critical destructive surface; world-readable would leak
	// the per-run RUNTIME_AUTH_TOKEN handshake.
	if err := rundir.WriteAtomic(dest, []byte(b.String()), 0o700); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}
