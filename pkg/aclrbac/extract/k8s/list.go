// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package k8s

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// listAll lists every CR matching gvr in the requested scope and returns
// the unstructured objects. Behavior:
//
//   - allNS=true → list across all namespaces (resource must be NS-scoped
//     in the API; cluster-scoped resources ignore namespace anyway).
//   - allNS=false, namespace="" → list cluster-scoped.
//   - allNS=false, namespace="X" → list only in X.
//   - labelSelector is the standard K8s selector string (e.g. "app=foo").
//
// CRD-not-installed (NotFound or NotImplemented on the resource kind)
// is treated as "no items" rather than an error so the adapter degrades
// gracefully on clusters that have only one of CFK / Strimzi installed.
func listAll(
	ctx context.Context,
	dyn dynamic.Interface,
	gvr schema.GroupVersionResource,
	namespace string,
	allNS bool,
	labelSelector string,
) ([]unstructured.Unstructured, error) {
	opts := metav1.ListOptions{LabelSelector: labelSelector}

	var ri dynamic.ResourceInterface
	switch {
	case allNS:
		ri = dyn.Resource(gvr) // omitting .Namespace() lists across all NS
	case namespace != "":
		ri = dyn.Resource(gvr).Namespace(namespace)
	default:
		ri = dyn.Resource(gvr)
	}

	list, err := ri.List(ctx, opts)
	if err != nil {
		// CRD missing on this cluster: graceful empty result.
		if apierrors.IsNotFound(err) || apierrors.IsMethodNotSupported(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("k8s: list %s: %w", gvr.String(), err)
	}
	return list.Items, nil
}
