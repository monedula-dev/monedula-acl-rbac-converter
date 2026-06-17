// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package config parses and validates the YAML config files documented in
// spec §5.1: scopes.yaml, rules.yaml, principals.yaml, ack.yaml. The
// rules-merge logic also lives here (defaults + overrides).
package config

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// ParseScopes parses scopes.yaml.
//
// Validation that the *required* fields are present is deferred to the planner
// (§5.1: "only the cluster IDs needed for the actual bindings are required").
// This function only validates parseability.
func ParseScopes(data []byte) (types.Scope, error) {
	var raw struct {
		Organization          string `yaml:"organization"`
		Environment           string `yaml:"environment"`
		KafkaCluster          string `yaml:"kafka_cluster"`
		SchemaRegistryCluster string `yaml:"schema_registry_cluster"`
		KSQLCluster           string `yaml:"ksql_cluster"`
		ConnectCluster        string `yaml:"connect_cluster"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return types.Scope{}, fmt.Errorf("parse scopes.yaml: %w", err)
	}
	return types.Scope{
		Organization:          raw.Organization,
		Environment:           raw.Environment,
		KafkaCluster:          raw.KafkaCluster,
		SchemaRegistryCluster: raw.SchemaRegistryCluster,
		KSQLCluster:           raw.KSQLCluster,
		ConnectCluster:        raw.ConnectCluster,
	}, nil
}
