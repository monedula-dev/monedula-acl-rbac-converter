// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package cfk renders a Plan as a multi-document YAML stream of
// ConfluentRolebinding CRs targeting CFK 2.x.
package cfk

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/emit"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

type Options struct {
	// Namespace fills metadata.namespace. Empty means "omit" (defers to
	// `kubectl apply -n`).
	Namespace string
}

type Emitter struct {
	opts Options
}

func New(opts Options) *Emitter { return &Emitter{opts: opts} }

func (e *Emitter) Name() string { return "cfk" }

func (e *Emitter) Emit(w io.Writer, plan types.Plan) (int, error) {
	created := 0
	var b strings.Builder
	for _, bd := range emit.OrderedBindings(plan.Bindings) {
		if bd.Action == types.ActionSkipExists {
			continue
		}
		created++
		// The CFK ConfluentRolebinding CRD has no organization/environment
		// (Confluent Cloud) scope. Surface a warning rather than silently
		// dropping a scope the plan asked for.
		if bd.Scope.Organization != "" || bd.Scope.Environment != "" {
			fmt.Fprintf(&b, "# WARNING: binding %s has organization/environment scope which the CFK ConfluentRolebinding CRD cannot represent; it is omitted\n",
				emit.SanitizeComment(bd.ID))
		}
		doc, err := marshalBindingDoc(bd, e.opts.Namespace)
		if err != nil {
			return created, fmt.Errorf("cfk: marshal binding %s: %w", bd.ID, err)
		}
		b.Write(doc)
		b.WriteString("---\n")
	}
	_, err := io.WriteString(w, b.String())
	return created, err
}

// The CR is marshalled from a typed struct via yaml.v3 rather than
// hand-written, so (a) field names match the real ConfluentRolebinding CRD
// (clustersScopeByIds.<cluster>Id, not the nonexistent kafkaClusterRef that
// Kubernetes silently prunes) and (b) every data-derived scalar (principal
// name, resource name, metadata.name) is YAML-quoted as needed, closing the
// injection/corruption vector that raw fmt.Fprintf left open.
type cfkDoc struct {
	APIVersion string  `yaml:"apiVersion"`
	Kind       string  `yaml:"kind"`
	Metadata   cfkMeta `yaml:"metadata"`
	Spec       cfkSpec `yaml:"spec"`
}

type cfkMeta struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace,omitempty"`
}

type cfkSpec struct {
	Principal          cfkPrincipal `yaml:"principal"`
	Role               string       `yaml:"role"`
	ResourcePatterns   []cfkRP      `yaml:"resourcePatterns,omitempty"`
	ClustersScopeByIds *cfkClusters `yaml:"clustersScopeByIds,omitempty"`
}

type cfkPrincipal struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}

type cfkRP struct {
	ResourceType string `yaml:"resourceType"`
	Name         string `yaml:"name"`
	PatternType  string `yaml:"patternType"`
}

type cfkClusters struct {
	KafkaClusterID          string `yaml:"kafkaClusterId,omitempty"`
	SchemaRegistryClusterID string `yaml:"schemaRegistryClusterId,omitempty"`
	KSQLClusterID           string `yaml:"ksqlClusterId,omitempty"`
	ConnectClusterID        string `yaml:"connectClusterId,omitempty"`
}

func marshalBindingDoc(bd types.Binding, namespace string) ([]byte, error) {
	pkind, pname := splitPrincipal(bd.Principal)
	doc := cfkDoc{
		APIVersion: "platform.confluent.io/v1beta1",
		Kind:       "ConfluentRolebinding",
		Metadata:   cfkMeta{Name: bd.ID, Namespace: namespace},
		Spec: cfkSpec{
			Principal: cfkPrincipal{Type: pkind, Name: pname},
			Role:      bd.Role,
		},
	}
	for _, rp := range bd.ResourcePatterns {
		doc.Spec.ResourcePatterns = append(doc.Spec.ResourcePatterns, cfkRP{
			ResourceType: string(rp.ResourceType),
			Name:         rp.Name,
			PatternType:  string(rp.PatternType),
		})
	}
	if c := scopeClusters(bd.Scope); c != nil {
		doc.Spec.ClustersScopeByIds = c
	}
	return yaml.Marshal(doc)
}

func splitPrincipal(p string) (kind, name string) {
	if strings.HasPrefix(p, "Group:") {
		return "group", strings.TrimPrefix(p, "Group:")
	}
	return "user", strings.TrimPrefix(p, "User:")
}

func scopeClusters(s types.Scope) *cfkClusters {
	c := cfkClusters{
		KafkaClusterID:          s.KafkaCluster,
		SchemaRegistryClusterID: s.SchemaRegistryCluster,
		KSQLClusterID:           s.KSQLCluster,
		ConnectClusterID:        s.ConnectCluster,
	}
	if c == (cfkClusters{}) {
		return nil
	}
	return &c
}
