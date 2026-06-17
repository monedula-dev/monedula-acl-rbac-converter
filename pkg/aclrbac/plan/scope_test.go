// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan_test

import (
	"strings"
	"testing"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/plan"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

func TestScope_TopicNeedsKafkaCluster(t *testing.T) {
	s := types.Scope{}
	err := plan.RequireScope(s, types.ResourceTopic)
	if err == nil {
		t.Fatal("expected error: Topic needs kafka_cluster")
	}
	if !strings.Contains(err.Error(), "kafka_cluster") {
		t.Errorf("error should mention kafka_cluster; got %v", err)
	}
}

func TestScope_TopicWithKafkaClusterOK(t *testing.T) {
	s := types.Scope{KafkaCluster: "lkc-kafka01"}
	if err := plan.RequireScope(s, types.ResourceTopic); err != nil {
		t.Errorf("kafka_cluster set, should succeed; got %v", err)
	}
}

func TestScope_SubjectNeedsSchemaRegistry(t *testing.T) {
	s := types.Scope{KafkaCluster: "lkc-kafka01"}
	err := plan.RequireScope(s, types.ResourceSubject)
	if err == nil {
		t.Fatal("expected error: Subject needs schema_registry_cluster")
	}
}

func TestApplyScopeForResource(t *testing.T) {
	s := types.Scope{
		Organization:          "123e4567-",
		Environment:           "env-abc",
		KafkaCluster:          "lkc-kafka01",
		SchemaRegistryCluster: "lsrc-sr01",
	}

	got := plan.ApplyScope(s, types.ResourceTopic)
	if got.KafkaCluster == "" {
		t.Errorf("Topic should carry kafka_cluster: %+v", got)
	}
	if got.SchemaRegistryCluster != "" {
		t.Errorf("Topic should NOT carry schema_registry_cluster: %+v", got)
	}

	got = plan.ApplyScope(s, types.ResourceSubject)
	if got.SchemaRegistryCluster == "" {
		t.Errorf("Subject should carry schema_registry_cluster: %+v", got)
	}
	if got.KafkaCluster != "" {
		t.Errorf("Subject should NOT carry kafka_cluster: %+v", got)
	}
}
