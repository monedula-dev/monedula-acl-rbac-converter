// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package k8s

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// buildRestConfig loads a kubeconfig file and returns a rest.Config along
// with the resolved API server URL (used to populate
// extract.ExtractSource.K8sServer for the audit trail). If kubeconfig is
// empty, clientcmd's standard precedence applies (KUBECONFIG env, then
// $HOME/.kube/config). If contextName is empty, the kubeconfig's
// current-context is used.
func buildRestConfig(kubeconfig, contextName string) (*rest.Config, string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	cfg, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("k8s: load kubeconfig: %w", err)
	}
	return cfg, cfg.Host, nil
}
