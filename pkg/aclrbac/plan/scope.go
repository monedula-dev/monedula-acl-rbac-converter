// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package plan

import (
	"fmt"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// RequireScope checks that scope has the cluster ID required for a binding
// targeting the given resource type. Conditional-required per spec §5.1.
func RequireScope(s types.Scope, rt types.ResourceType) error {
	switch rt {
	case types.ResourceTopic, types.ResourceGroup, types.ResourceTransactionalID,
		types.ResourceCluster, types.ResourceDelegationToken:
		if s.KafkaCluster == "" {
			return fmt.Errorf("scopes.yaml: kafka_cluster is required (binding targets %s)", rt)
		}
	case types.ResourceSubject:
		if s.SchemaRegistryCluster == "" {
			return fmt.Errorf("scopes.yaml: schema_registry_cluster is required (binding targets %s)", rt)
		}
	}
	return nil
}

// ApplyScope returns a scope value with only the cluster fields meaningful
// for this resource type. The other cluster IDs are blanked so they don't
// leak into the binding's serialized form.
func ApplyScope(s types.Scope, rt types.ResourceType) types.Scope {
	out := types.Scope{
		Organization: s.Organization,
		Environment:  s.Environment,
	}
	switch rt {
	case types.ResourceTopic, types.ResourceGroup, types.ResourceTransactionalID,
		types.ResourceCluster, types.ResourceDelegationToken:
		out.KafkaCluster = s.KafkaCluster
	case types.ResourceSubject:
		out.SchemaRegistryCluster = s.SchemaRegistryCluster
	}
	return out
}
