// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package k8s

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
)

// newFakeKafkaUser constructs a minimal KafkaUser CR for fake-client seeding.
func newFakeKafkaUser(namespace, name string, labels map[string]string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvrKafkaUser.GroupVersion().WithKind("KafkaUser"))
	u.SetName(name)
	u.SetNamespace(namespace)
	if labels != nil {
		u.SetLabels(labels)
	}
	return u
}

// newFakeDyn builds a fake.Interface that knows the list-kind for every
// GVR the adapter uses. Required because the dynamic client needs to
// map each kind to a list kind, and for arbitrary CRDs that mapping
// isn't auto-discovered.
func newFakeDyn(objects ...runtime.Object) dynamic.Interface {
	listKinds := map[schema.GroupVersionResource]string{
		gvrKafkaUser:            "KafkaUserList",
		gvrKafkaCFK:             "KafkaList",
		gvrConfluentRolebinding: "ConfluentRolebindingList",
	}
	return fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)
}

func TestListAll_SingleNamespace(t *testing.T) {
	dyn := newFakeDyn(
		newFakeKafkaUser("teamA", "alice", nil),
		newFakeKafkaUser("teamB", "bob", nil),
	)
	got, err := listAll(context.Background(), dyn, gvrKafkaUser, "teamA", false, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 item in teamA; got %d", len(got))
	}
}

func TestListAll_AllNamespaces(t *testing.T) {
	dyn := newFakeDyn(
		newFakeKafkaUser("teamA", "alice", nil),
		newFakeKafkaUser("teamB", "bob", nil),
	)
	got, err := listAll(context.Background(), dyn, gvrKafkaUser, "", true, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 items across all namespaces; got %d", len(got))
	}
}

func TestListAll_LabelSelector(t *testing.T) {
	dyn := newFakeDyn(
		newFakeKafkaUser("teamA", "alice", map[string]string{"app": "billing"}),
		newFakeKafkaUser("teamA", "bob", map[string]string{"app": "search"}),
	)
	got, err := listAll(context.Background(), dyn, gvrKafkaUser, "teamA", false, "app=billing")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("label selector should yield 1; got %d", len(got))
	}
	if got[0].GetName() != "alice" {
		t.Errorf("wrong object: %s", got[0].GetName())
	}
}

func TestListAll_MissingCRDIsSkipped(t *testing.T) {
	// Fake client with no objects of this GVR returns empty, not error.
	// In production, the K8s API returns NotFound when the CRD itself
	// isn't installed; listAll should classify that as "skip, log".
	dyn := newFakeDyn()
	got, err := listAll(context.Background(), dyn, gvrConfluentRolebinding, "", true, "")
	if err != nil {
		t.Errorf("missing CRD must not be a hard error; got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d items; want 0", len(got))
	}
}
