// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package k8s extracts ACLs from a running Kubernetes cluster by listing
// Strimzi KafkaUser CRs and CFK Kafka / ConfluentRolebinding CRs via the
// dynamic client. The unstructured CR objects are re-serialized to YAML
// and routed through the existing strimzi/cfk parsers so all three
// adapters share one canonical YAML→IR path.
//
// Authentication uses the standard kubeconfig precedence (clientcmd):
// --kubeconfig overrides $KUBECONFIG which overrides $HOME/.kube/config.
// --context selects a non-default context. SASL/TLS to the Kafka cluster
// itself is not needed here — we only talk to the K8s API server.
package k8s

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	extractcfk "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/cfk"
	extractstrimzi "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/strimzi"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// listTimeout caps each List call. The default matches client-go's
// recommended ceiling for interactive operations.
const listTimeout = 30 * time.Second

// listFunc is the indirection point for the List call, overridable in tests.
var listFunc = listAll

// Options bundles the connection and scope flags.
type Options struct {
	Kubeconfig    string
	Context       string
	Namespace     string
	AllNamespaces bool
	LabelSelector string
}

// Adapter is the live-K8s adapter.
type Adapter struct {
	opts Options
}

// dynBuild is the injection point for tests. Production uses the
// kubeconfig-loading implementation; tests override it to return a
// fake.Interface and a canned server URL.
var dynBuild = func(kubeconfig, contextName string) (dynamic.Interface, string, error) {
	cfg, server, err := buildRestConfig(kubeconfig, contextName)
	if err != nil {
		return nil, "", err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("k8s: build dynamic client: %w", err)
	}
	return dyn, server, nil
}

// New constructs an Adapter.
func New(opts Options) (*Adapter, error) {
	if opts.Namespace == "" && !opts.AllNamespaces && opts.LabelSelector == "" {
		return nil, fmt.Errorf("k8s adapter: pick a scope (--namespace, --all-namespaces, or --label-selector)")
	}
	return &Adapter{opts: opts}, nil
}

func (a *Adapter) Name() string { return "k8s" }

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()

	dyn, server, err := dynBuild(a.opts.Kubeconfig, a.opts.Context)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
	}

	var (
		allRows     []types.ACLRow
		allBindings []types.Binding
		seenNS      = map[string]bool{}
	)

	for _, gvr := range allGVRs() {
		// listTimeout caps EACH List call, so give every call its own fresh
		// timeout context rather than sharing one cumulative budget across all
		// GVRs (a slow first list would otherwise eat into the later ones).
		items, err := func() ([]unstructured.Unstructured, error) {
			ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
			defer cancel()
			return listFunc(ctx, dyn, gvr, a.opts.Namespace, a.opts.AllNamespaces, a.opts.LabelSelector)
		}()
		if err != nil {
			return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
		}
		if len(items) == 0 {
			log.Logf("LIST %s: no objects (CRD may not be installed)", gvr.String())
			continue
		}
		log.Logf("LIST %s: %d objects", gvr.String(), len(items))

		for i := range items {
			seenNS[items[i].GetNamespace()] = true
			yamlBytes, err := yaml.Marshal(items[i].Object)
			if err != nil {
				log.Logf("WARN %s/%s: marshal: %v", items[i].GetNamespace(), items[i].GetName(), err)
				continue
			}

			switch gvr {
			case gvrKafkaUser:
				rows, err := extractstrimzi.ParseStream(yamlBytes, log)
				if err != nil {
					log.Logf("WARN %s/%s: strimzi parse: %v", items[i].GetNamespace(), items[i].GetName(), err)
					continue
				}
				allRows = append(allRows, rows...)
			case gvrKafkaCFK, gvrConfluentRolebinding:
				rows, bindings, _ := extractcfk.ParseStream(yamlBytes, 1, log)
				allRows = append(allRows, rows...)
				allBindings = append(allBindings, bindings...)
			}
		}
	}

	// Globally renumber IDs 1..N. Per-parser numbering was relative; the
	// canonical IR requires unique IDs across the set.
	for i := range allRows {
		allRows[i].ID = i + 1
	}

	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "k8s", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          allRows,
	}
	src := extract.ExtractSource{
		Kind:          "k8s",
		K8sServer:     server,
		K8sNamespaces: sortedKeys(seenNS),
		Timestamp:     time.Now().UTC(),
	}
	log.Logf("EXTRACTED %d ACLs and %d existing-bindings from %s", len(allRows), len(allBindings), server)
	return set, allBindings, src, log, nil
}

// sortedKeys returns the keys of m in ascending order, dropping empties.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k == "" {
			continue
		}
		out = append(out, k)
	}
	// Insertion sort — small N (one element per namespace touched).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
