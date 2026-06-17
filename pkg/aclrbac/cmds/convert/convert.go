// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package convert implements `monedula-acl-rbac convert` — a stateless
// one-shot extract → plan → emit pipeline that writes to stdout (or --out).
package convert

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/cfk"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/mdscurl"
	emitscript "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit/script"
	extractcfk "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/cfk"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/csv"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/jsonyaml"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/script"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/strimzi"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/text"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Options feed Run.
type Options struct {
	From           string
	InputPath      string
	ScopesPath     string
	RulesPath      string
	PrincipalsPath string
	EmitFormat     string

	// Script-source options. Ignored unless From == "script" (or
	// auto-detected from a .sh file).
	Vars         map[string]string
	IgnoreNonAdd bool
	// VarsFile, if non-empty, overrides Vars by loading the YAML file via
	// script.LoadVars. CLI usage typically sets this; library usage may
	// set Vars directly.
	VarsFile string

	// CFK emit options.
	CFKNamespace string
	CFKNameSalt  string
}

// Run executes extract → plan → emit in one shot and writes to w.
func Run(w io.Writer, opts Options) error {
	from := opts.From
	if from == "" {
		from = autoDetect(opts.InputPath)
	}
	if from == "" {
		return fmt.Errorf("convert: --from required (cannot auto-detect from %q)", opts.InputPath)
	}

	set, err := extractFromSource(from, opts)
	if err != nil {
		return err
	}

	scopeData, err := os.ReadFile(opts.ScopesPath)
	if err != nil {
		return err
	}
	scope, err := config.ParseScopes(scopeData)
	if err != nil {
		return err
	}
	defaults, _ := config.DefaultRulesYAML()
	rules, err := config.ParseRules(defaults)
	if err != nil {
		return err
	}
	if opts.RulesPath != "" {
		overrideData, err := os.ReadFile(opts.RulesPath)
		if err != nil {
			return err
		}
		overrides, err := config.ParseRules(overrideData)
		if err != nil {
			return err
		}
		rules = config.MergeRules(rules, overrides)
	}
	var principals config.Principals
	if opts.PrincipalsPath != "" {
		pdata, err := os.ReadFile(opts.PrincipalsPath)
		if err != nil {
			return err
		}
		principals, err = config.ParsePrincipals(pdata)
		if err != nil {
			return err
		}
	} else {
		principals = config.Principals{Fallback: config.PrincipalFallbackPassThrough}
	}

	p, err := plan.Run(plan.Input{
		ACLs:        set,
		Rules:       rules,
		Principals:  principals,
		Scopes:      scope,
		CFKNameSalt: opts.CFKNameSalt,
	})
	if err != nil {
		return err
	}

	switch opts.EmitFormat {
	case "", "script":
		// PlanPath is empty: convert builds an in-memory Plan from the input
		// (acls file or live source) — there is no plan.json on disk to
		// reference. Passing opts.InputPath here would have mislabelled the
		// audit header as `# Plan: acls.yaml`, which is structurally wrong.
		_, err = emitscript.New(emitscript.Options{PlanPath: ""}).Emit(w, p)
	case "cfk":
		_, err = cfk.New(cfk.Options{Namespace: opts.CFKNamespace}).Emit(w, p)
	case "mds-curl":
		_, err = mdscurl.New(mdscurl.Options{PlanPath: ""}).Emit(w, p)
	default:
		return fmt.Errorf("convert: unknown --format %q", opts.EmitFormat)
	}
	return err
}

func autoDetect(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	case ".sh":
		return "script"
	case ".txt":
		return "text"
	}
	return ""
}

func extractFromSource(from string, opts Options) (types.ACLSet, error) {
	path := opts.InputPath
	switch from {
	case "json", "yaml":
		a, _ := jsonyaml.New(path)
		s, _, _, _, err := a.Extract()
		return s, err
	case "csv":
		a, _ := csv.New(path)
		s, _, _, _, err := a.Extract()
		return s, err
	case "text":
		a, _ := text.New(path)
		s, _, _, _, err := a.Extract()
		return s, err
	case "script":
		vars := opts.Vars
		if opts.VarsFile != "" {
			loaded, err := script.LoadVars(opts.VarsFile)
			if err != nil {
				return types.ACLSet{}, fmt.Errorf("convert: load --vars: %w", err)
			}
			vars = loaded
		}
		a, _ := script.New(path, vars, opts.IgnoreNonAdd)
		s, _, _, _, err := a.Extract()
		return s, err
	case "strimzi":
		a, _ := strimzi.New(path)
		s, _, _, _, err := a.Extract()
		return s, err
	case "cfk":
		a, _ := extractcfk.New(path)
		s, _, _, _, err := a.Extract()
		return s, err
	}
	if from == "live" || from == "k8s" {
		return types.ACLSet{}, fmt.Errorf("convert: --from %q is not supported here (convert is stateless; use `extract --from %s` + `plan` for live/k8s sources to get the run-dir audit trail)", from, from)
	}
	return types.ACLSet{}, fmt.Errorf("convert: unsupported --from %q (try text|json|yaml|csv|strimzi|cfk|script)", from)
}
