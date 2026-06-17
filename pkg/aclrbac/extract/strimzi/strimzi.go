// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package strimzi parses Strimzi KafkaUser CRs into canonical ACL rows.
package strimzi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

type Adapter struct {
	path string
}

func New(path string) (*Adapter, error) {
	return &Adapter{path: path}, nil
}

func (a *Adapter) Name() string { return "strimzi" }

type strimziDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		Authorization struct {
			Type string `yaml:"type"`
			ACLs []struct {
				Resource struct {
					Type        string `yaml:"type"`
					Name        string `yaml:"name"`
					PatternType string `yaml:"patternType"`
				} `yaml:"resource"`
				Operations []string `yaml:"operations"`
				// Operation is the deprecated singular form still present in
				// older KafkaUser manifests (e.g. `operation: Read`). It is the
				// fallback when `operations` is absent.
				Operation string `yaml:"operation"`
				Host      string `yaml:"host"`
				Type      string `yaml:"type"`
			} `yaml:"acls"`
		} `yaml:"authorization"`
	} `yaml:"spec"`
}

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("read %s: %w", a.path, err)
	}

	rows, err := ParseStream(data, log)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
	}

	sum := sha256.Sum256(data)
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "strimzi", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          rows,
	}
	src := extract.ExtractSource{
		Kind:        "strimzi",
		InputPath:   a.path,
		InputSHA256: hex.EncodeToString(sum[:]),
		Timestamp:   time.Now().UTC(),
	}
	return set, nil, src, log, nil
}

// ParseStream parses one multi-doc YAML stream of Strimzi CRs and returns
// canonical ACL rows. Only `KafkaUser` documents produce rows; everything
// else is logged and skipped. IDs start at 1 within the returned slice;
// callers that concatenate multiple streams should renumber globally.
//
// Exported so the k8s live-extractor can feed CR YAML through it without
// going through the file system.
func ParseStream(data []byte, log *extract.Logger) ([]types.ACLRow, error) {
	var rows []types.ACLRow
	id := 1

	for _, doc := range bytesSplitYAMLDocs(data) {
		var d strimziDoc
		if err := yaml.Unmarshal(doc, &d); err != nil {
			// Mirror the CFK extractor's tolerance: a single malformed doc in
			// a multi-doc stream (e.g. `kubectl get kafkausers -o yaml`)
			// shouldn't poison every other doc. Log and continue rather than
			// aborting the whole extract.
			log.Logf("WARN malformed doc: %v", err)
			continue
		}
		if d.Kind != "KafkaUser" {
			log.Logf("SKIPPED non-KafkaUser doc kind=%q", d.Kind)
			continue
		}
		if d.Spec.Authorization.Type != "simple" {
			log.Logf("WARN KafkaUser %s/%s authorization type=%q (only `simple` produces ACLs)",
				d.Metadata.Namespace, d.Metadata.Name, d.Spec.Authorization.Type)
			continue
		}
		principal := "User:" + d.Metadata.Name
		for _, acl := range d.Spec.Authorization.ACLs {
			host := acl.Host
			if host == "" {
				host = "*"
			}
			perm := types.PermissionAllow
			if strings.EqualFold(acl.Type, "deny") {
				perm = types.PermissionDeny
			}
			pat := strimziPatternType(acl.Resource.PatternType, log)
			rt := strimziResourceType(acl.Resource.Type)
			ops := acl.Operations
			if len(ops) == 0 && acl.Operation != "" {
				ops = []string{acl.Operation}
			}
			for _, op := range ops {
				rows = append(rows, types.ACLRow{
					ID:             id,
					Principal:      principal,
					Host:           host,
					Operation:      types.Operation(op),
					ResourceType:   rt,
					ResourceName:   acl.Resource.Name,
					PatternType:    pat,
					PermissionType: perm,
				})
				id++
			}
		}
	}
	return rows, nil
}

// strimziPatternType maps Strimzi's resource.patternType enum (literal/prefix)
// to the canonical IR pattern types. Strimzi uses `prefix`, which must become
// PREFIXED — uppercasing it to "PREFIX" yields a value that exists nowhere in
// the IR. An empty value defaults to LITERAL (Strimzi's own default).
func strimziPatternType(s string, log *extract.Logger) types.PatternType {
	switch strings.ToLower(s) {
	case "", "literal":
		return types.PatternLiteral
	case "prefix":
		return types.PatternPrefixed
	default:
		log.Logf("WARN unknown Strimzi patternType %q; treating as literal", s)
		return types.PatternLiteral
	}
}

func strimziResourceType(t string) types.ResourceType {
	switch strings.ToLower(t) {
	case "topic":
		return types.ResourceTopic
	case "group":
		return types.ResourceGroup
	case "cluster":
		return types.ResourceCluster
	case "transactionalid", "transactional-id":
		return types.ResourceTransactionalID
	}
	return types.ResourceType(t)
}

// bytesSplitYAMLDocs splits a multi-doc YAML stream by the `---` separator.
func bytesSplitYAMLDocs(data []byte) [][]byte {
	parts := strings.Split(string(data), "\n---")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimPrefix(p, "---")
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, []byte(p))
	}
	return out
}
