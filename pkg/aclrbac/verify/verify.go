// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package verify checks bindings in MDS, in either `bindings-exist` mode
// (binding rows present) or `effective` mode (per-source-ACL effective
// access reported as allowed). Spec §11.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/rundir"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Mode chooses the verification strategy.
type Mode string

const (
	ModeBindingsExist Mode = "bindings-exist"
	ModeEffective     Mode = "effective"
)

// Status is the per-row outcome.
type Status string

const (
	StatusBindingExists  Status = "BINDING_EXISTS"
	StatusBindingMissing Status = "BINDING_MISSING"
	// StatusBindingUnknown means MDS could not be queried for this binding
	// (transient/operational error) — distinct from "the binding is absent".
	StatusBindingUnknown   Status = "BINDING_UNKNOWN"
	StatusEffectiveOK      Status = "EFFECTIVE_OK"
	StatusEffectiveMissing Status = "EFFECTIVE_MISSING"
	StatusEffectiveUnknown Status = "EFFECTIVE_UNKNOWN"
)

// Result is one entry per (mode-specific) row. For bindings-exist mode the
// "row" is one binding; for effective mode it's one source ACL.
type Result struct {
	BindingID   string `json:"binding_id,omitempty"`
	SourceACLID int    `json:"source_acl_id,omitempty"`
	Status      Status `json:"status"`
	Detail      string `json:"detail,omitempty"`
}

// ResourceRef identifies a resource for effective-mode lookups.
type ResourceRef struct {
	Type    types.ResourceType
	Name    string
	Pattern types.PatternType
}

// Options bundles inputs.
type Options struct {
	RunDir        string
	PlanPath      string
	Client        *mds.Client
	Mode          Mode
	Parallelism   int
	AcceptUnknown bool
	// SourceOps and SourceResources are required for ModeEffective.
	// The CLI populates them by reading acls.json from the run dir.
	SourceOps       map[int]types.Operation
	SourceResources map[int]ResourceRef
	Progress        *Progress // optional; non-nil enables per-binding progress output

	// OutPath, if non-empty, overrides the default
	// <RunDir>/verify.json output location. The CLI threads
	// --out into this field; library callers may set it directly.
	OutPath string

	// SummaryWriter, if non-nil, receives a structured summary after
	// Run completes. The CLI sets this to os.Stdout when the user
	// passes --format. The format defaults to FormatText if
	// SummaryFormat is empty.
	SummaryWriter io.Writer
	SummaryFormat Format
}

// Run executes verification and writes verify.json into the run directory.
func Run(opts Options) ([]Result, error) {
	if err := rundir.VerifyChecksum(opts.PlanPath); err != nil {
		return nil, err
	}
	// Compute the plan's SHA-256 from disk and stamp it into verify.json so
	// delete-* can refuse a verify.json generated against a different plan.
	// We hash the raw plan.json bytes (matching common.FileSHA256 /
	// rundir.WriteChecksum) rather than trusting the .sha256 sibling, which
	// VerifyChecksum has already confirmed matches the file content above.
	planSHA, err := fileSHA256(opts.PlanPath)
	if err != nil {
		return nil, err
	}
	plan, err := rundir.ReadPlan(opts.PlanPath)
	if err != nil {
		return nil, err
	}

	prog := opts.Progress
	if prog == nil {
		prog = NewProgress(false)
	}

	var results []Result
	mode := opts.Mode
	switch opts.Mode {
	case ModeBindingsExist, "":
		mode = ModeBindingsExist
		results, err = verifyBindingsExist(opts.Client, plan, prog, opts.Parallelism)
	case ModeEffective:
		results, err = verifyEffective(opts.Client, plan, opts.SourceOps, opts.SourceResources, prog, opts.Parallelism)
	default:
		return nil, fmt.Errorf("verify: unknown mode %q", opts.Mode)
	}
	if err != nil {
		return nil, err
	}

	// --accept-unknown-verify (README "Step 4"): treat EFFECTIVE_UNKNOWN as
	// EFFECTIVE_OK so delete-acls' eligibility check accepts the row. We
	// downgrade in a post-pass rather than inside the per-row classifier so
	// the original status survives in any structured logging that runs
	// before Run returns, and so the Detail field preserves the reason the
	// row was unknown plus the marker that the operator opted into
	// accepting it.
	if opts.AcceptUnknown {
		for i := range results {
			if results[i].Status == StatusEffectiveUnknown {
				results[i].Status = StatusEffectiveOK
				if results[i].Detail == "" {
					results[i].Detail = "downgraded by --accept-unknown-verify"
				} else {
					results[i].Detail = results[i].Detail + " (downgraded by --accept-unknown-verify)"
				}
			}
		}
	}

	// verify.json on disk uses the same {results, counts} envelope as
	// `verify --format json` on stdout. Operators can pipe both through
	// the same jq filters; CI consumers can validate against
	// schemas/verify-summary.v1.json.
	diskSummary := Summary{SchemaVersion: CurrentSchemaVersion, PlanSHA256: planSHA, Mode: string(mode), Results: results}
	diskSummary.Counts = diskSummary.AggregateCounts()
	data, _ := json.MarshalIndent(diskSummary, "", "  ")
	out := opts.OutPath
	if out == "" {
		out = filepath.Join(opts.RunDir, "verify.json")
	}
	if err := rundir.WriteAtomic(out, data, 0o600); err != nil {
		return nil, fmt.Errorf("write verify.json: %w", err)
	}

	// Render summary regardless of any partial failure — operators
	// rely on the per-result rows when triaging. Mirrors apply.Run's
	// tail block.
	if opts.SummaryWriter != nil {
		sum := Summary{PlanSHA256: planSHA, Mode: string(mode), Results: results}
		format := opts.SummaryFormat
		if format == "" {
			format = FormatText
		}
		var sumErr error
		switch format {
		case FormatJSON:
			sumErr = sum.WriteJSON(opts.SummaryWriter)
		default:
			sumErr = sum.WriteText(opts.SummaryWriter)
		}
		if sumErr != nil {
			return results, fmt.Errorf("write summary: %w", sumErr)
		}
	}

	return results, nil
}

// fileSHA256 returns the hex-encoded SHA-256 of the file at path. Matches
// common.FileSHA256 / rundir.WriteChecksum so the stamped value is
// byte-comparable against plan.json.sha256.
func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// defaultParallelism matches the --verify-parallelism flag default.
const defaultParallelism = 8

// maxParallelism is an operator-friendly soft cap. Beyond this, a 100ms
// MDS easily tips into rate-limiting / connection-exhaustion territory,
// and the marginal latency win shrinks. We clamp rather than error so an
// over-eager --verify-parallelism never fails the run.
const maxParallelism = 64

// clampParallelism normalises the requested worker count: <=0 falls back
// to the default, and anything above the soft cap is clamped down.
func clampParallelism(p int) int {
	if p <= 0 {
		return defaultParallelism
	}
	if p > maxParallelism {
		return maxParallelism
	}
	return p
}
