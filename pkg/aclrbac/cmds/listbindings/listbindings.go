// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package listbindings implements `monedula-acl-rbac mds list-bindings`.
package listbindings

import (
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/mds"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Format selects output.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// CurrentSchemaVersion is stamped into JSON/YAML envelopes, matching the
// apply / verify / status / report / diff convention.
const CurrentSchemaVersion = "1"

// Report is the JSON/YAML envelope returned by `mds list-bindings
// --format json|yaml`.
type Report struct {
	SchemaVersion string          `json:"schema_version" yaml:"schema_version"`
	Bindings      []types.Binding `json:"bindings"       yaml:"bindings"`
}

// Options bundles inputs.
type Options struct {
	Client          *mds.Client
	PrincipalFilter []string
	ScopeFilter     []string
	// Scope is the MDS lookup scope (cluster IDs). The real MDS rolebindings
	// lookup is per-principal at a scope; there is no "all principals"
	// endpoint, so PrincipalFilter and a Kafka cluster scope are required.
	Scope  types.Scope
	Format Format
}

// Run executes the listing.
func Run(w io.Writer, opts Options) error {
	if len(opts.PrincipalFilter) == 0 {
		return fmt.Errorf("mds list-bindings: --principal-filter is required (MDS has no all-principals lookup endpoint)")
	}
	if opts.Scope == (types.Scope{}) {
		return fmt.Errorf("mds list-bindings: a scope is required (e.g. --kafka-cluster <id>)")
	}
	var all []types.Binding
	for _, p := range opts.PrincipalFilter {
		bindings, err := mds.ListBindings(opts.Client, p, opts.Scope)
		if err != nil {
			return err
		}
		all = append(all, bindings...)
	}
	if len(opts.ScopeFilter) > 0 {
		all = filterByScope(all, opts.ScopeFilter)
	}

	// Bindings should marshal as [] not null when empty so downstream
	// consumers can iterate unconditionally.
	if all == nil {
		all = []types.Binding{}
	}

	switch opts.Format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(Report{SchemaVersion: CurrentSchemaVersion, Bindings: all})
	case FormatYAML:
		return yaml.NewEncoder(w).Encode(Report{SchemaVersion: CurrentSchemaVersion, Bindings: all})
	default:
		for _, b := range all {
			fmt.Fprintf(w, "%s\t%s\t%v\t%+v\n", b.Principal, b.Role, b.Scope, b.ResourcePatterns)
		}
		return nil
	}
}

func filterByScope(in []types.Binding, scopes []string) []types.Binding {
	want := map[string]bool{}
	for _, s := range scopes {
		want[s] = true
	}
	var out []types.Binding
	for _, b := range in {
		if want["kafka-cluster"] && b.Scope.KafkaCluster != "" {
			out = append(out, b)
			continue
		}
		if want["sr-cluster"] && b.Scope.SchemaRegistryCluster != "" {
			out = append(out, b)
			continue
		}
		if want["ksql-cluster"] && b.Scope.KSQLCluster != "" {
			out = append(out, b)
			continue
		}
		if want["connect-cluster"] && b.Scope.ConnectCluster != "" {
			out = append(out, b)
			continue
		}
		if want["organization"] && b.Scope.Organization != "" {
			out = append(out, b)
			continue
		}
		if want["environment"] && b.Scope.Environment != "" {
			out = append(out, b)
			continue
		}
	}
	return out
}
