// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package k8s

import "k8s.io/apimachinery/pkg/runtime/schema"

// CR GroupVersionResources the live K8s adapter lists.
//
// Versions are pinned to the most common shipping releases. If a cluster
// has a different version installed for any CRD, the list call returns
// NotFound and the adapter logs + continues (no hard error).
var (
	gvrKafkaUser = schema.GroupVersionResource{
		Group:    "kafka.strimzi.io",
		Version:  "v1beta2",
		Resource: "kafkausers",
	}
	gvrKafkaCFK = schema.GroupVersionResource{
		Group:    "platform.confluent.io",
		Version:  "v1beta1",
		Resource: "kafkas",
	}
	gvrConfluentRolebinding = schema.GroupVersionResource{
		Group:    "platform.confluent.io",
		Version:  "v1beta1",
		Resource: "confluentrolebindings",
	}
)

// allGVRs returns the list of GVRs to iterate in Extract; order is
// deterministic (Strimzi first, then CFK Kafka, then CFK rolebindings)
// so the canonical ACL rows come out in a stable shape across runs.
func allGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		gvrKafkaUser,
		gvrKafkaCFK,
		gvrConfluentRolebinding,
	}
}
