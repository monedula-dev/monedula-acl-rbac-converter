// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package config_test

import (
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/config"
)

func TestParseScopes_KafkaOnly(t *testing.T) {
	data := []byte(`kafka_cluster: lkc-kafka01`)
	got, err := config.ParseScopes(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.KafkaCluster != "lkc-kafka01" {
		t.Errorf("kafka_cluster: got %q, want lkc-kafka01", got.KafkaCluster)
	}
}

func TestParseScopes_All(t *testing.T) {
	data := []byte(`
organization: 123e4567-e89b-12d3-a456-426614174000
environment: env-abc123
kafka_cluster: lkc-kafka01
schema_registry_cluster: lsrc-sr01
ksql_cluster: lksqlc-ksql01
connect_cluster: lcc-connect01
`)
	got, err := config.ParseScopes(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.SchemaRegistryCluster != "lsrc-sr01" {
		t.Errorf("sr: got %q", got.SchemaRegistryCluster)
	}
}

func TestParseScopes_BadYAML(t *testing.T) {
	data := []byte(`kafka_cluster: [unterminated`)
	_, err := config.ParseScopes(data)
	if err == nil {
		t.Fatal("expected error for bad YAML")
	}
	if !strings.Contains(err.Error(), "yaml") && !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention yaml or parse; got %v", err)
	}
}
