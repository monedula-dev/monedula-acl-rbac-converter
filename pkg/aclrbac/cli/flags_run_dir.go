// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
)

// RunDirFlags hold <run-dir> values.
type RunDirFlags struct {
	RunDir string
	Out    string
}

// AddRunDirFlags wires --run-dir and --out.
func (f *RunDirFlags) AddRunDirFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.RunDir, "run-dir", "", "Explicit run directory")
	cmd.Flags().StringVar(&f.Out, "out", "", "Output path; parent dir becomes the run dir")
}

// Resolve returns the resolved run directory for an invocation.
func (f *RunDirFlags) Resolve(inputArtifact string) (string, error) {
	dir, err := rundir.Resolve(rundir.ResolveOptions{
		ExplicitRunDir: f.RunDir,
		Out:            f.Out,
		InputArtifact:  inputArtifact,
	})
	if err != nil {
		return "", err
	}
	if err := rundir.Ensure(dir); err != nil {
		return "", err
	}
	return dir, nil
}
