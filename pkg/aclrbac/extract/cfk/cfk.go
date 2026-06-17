// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package cfk parses CFK (Confluent for Kubernetes) manifests on disk into
// canonical ACL rows. Kafka CR superusers become ALL-on-Cluster ACLs;
// ConfluentRolebinding CRs are collected into a sidecar so the planner can
// mark already-applied bindings as SKIP_EXISTS.
package cfk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

type Adapter struct {
	path string // file or directory
}

func New(path string) (*Adapter, error) {
	return &Adapter{path: path}, nil
}

func (a *Adapter) Name() string { return "cfk" }

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()

	files, err := walkYAMLFiles(a.path)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
	}

	var rows []types.ACLRow
	var bindings []types.Binding
	id := 1
	hasher := sha256.New()

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("read %s: %w", f, err)
		}
		hasher.Write(data)
		fileRows, fileBindings, n := ParseStream(data, id, log)
		rows = append(rows, fileRows...)
		bindings = append(bindings, fileBindings...)
		id = n
	}

	// Stable order for tests.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Principal != rows[j].Principal {
			return rows[i].Principal < rows[j].Principal
		}
		return rows[i].Operation < rows[j].Operation
	})

	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "cfk", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          rows,
	}
	src := extract.ExtractSource{
		Kind:        "cfk",
		InputPath:   a.path,
		InputSHA256: hex.EncodeToString(hasher.Sum(nil)),
		Timestamp:   time.Now().UTC(),
	}

	return set, bindings, src, log, nil
}

// ParseStream parses one multi-doc YAML stream of CFK CRs into canonical
// ACL rows and a list of inventoried ConfluentRolebinding records. IDs in
// the returned rows start at startID; the function also returns nextID
// (= startID + len(rows)) so callers iterating multiple streams can
// continue numbering deterministically.
//
// Exported so the k8s live-extractor can feed CR YAML through it without
// going through the file system.
func ParseStream(data []byte, startID int, log *extract.Logger) (rows []types.ACLRow, bindings []types.Binding, nextID int) {
	id := startID
	for _, doc := range bytesSplitYAMLDocs(data) {
		var head struct {
			Kind string `yaml:"kind"`
		}
		if err := yaml.Unmarshal(doc, &head); err != nil {
			log.Logf("WARN malformed doc: %v", err)
			continue
		}
		switch head.Kind {
		case "Kafka":
			newRows, n := parseKafkaCR(doc, id, log)
			rows = append(rows, newRows...)
			id = n
		case "ConfluentRolebinding":
			b, err := parseRolebindingCR(doc)
			if err != nil {
				log.Logf("WARN malformed ConfluentRolebinding: %v", err)
				continue
			}
			bindings = append(bindings, b)
			log.Logf("INVENTORIED ConfluentRolebinding %s (existing)", b.Principal)
		default:
			if head.Kind != "" {
				log.Logf("SKIPPED unsupported kind %q", head.Kind)
			}
		}
	}
	return rows, bindings, id
}

func parseKafkaCR(doc []byte, startID int, log *extract.Logger) ([]types.ACLRow, int) {
	var k struct {
		Spec struct {
			Authorization struct {
				Type       string   `yaml:"type"`
				SuperUsers []string `yaml:"superUsers"`
			} `yaml:"authorization"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(doc, &k); err != nil {
		log.Logf("WARN Kafka CR malformed: %v", err)
		return nil, startID
	}
	t := strings.ToLower(k.Spec.Authorization.Type)
	if t != "simple" && t != "rbac" {
		log.Logf("WARN Kafka CR authorization type=%q (only simple/rbac supported)", t)
		return nil, startID
	}
	var rows []types.ACLRow
	id := startID
	for _, su := range k.Spec.Authorization.SuperUsers {
		rows = append(rows, types.ACLRow{
			ID:             id,
			Principal:      su,
			Host:           "*",
			Operation:      types.OpAll,
			ResourceType:   types.ResourceCluster,
			ResourceName:   "kafka-cluster",
			PatternType:    types.PatternLiteral,
			PermissionType: types.PermissionAllow,
		})
		id++
		log.Logf("PARSED Kafka superUser %s -> ALL on Cluster", su)
	}
	return rows, id
}

func parseRolebindingCR(doc []byte) (types.Binding, error) {
	// Field names follow the real CFK ConfluentRolebinding CRD
	// (platform.confluent.io/v1beta1): scope is expressed via
	// spec.clustersScopeByIds.<cluster>Id, NOT a (nonexistent) kafkaClusterRef.
	var rb struct {
		Spec struct {
			Principal struct {
				Type string `yaml:"type"`
				Name string `yaml:"name"`
			} `yaml:"principal"`
			Role             string `yaml:"role"`
			ResourcePatterns []struct {
				ResourceType string `yaml:"resourceType"`
				Name         string `yaml:"name"`
				PatternType  string `yaml:"patternType"`
			} `yaml:"resourcePatterns"`
			ClustersScopeByIds struct {
				KafkaClusterID          string `yaml:"kafkaClusterId"`
				SchemaRegistryClusterID string `yaml:"schemaRegistryClusterId"`
				KSQLClusterID           string `yaml:"ksqlClusterId"`
				ConnectClusterID        string `yaml:"connectClusterId"`
			} `yaml:"clustersScopeByIds"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(doc, &rb); err != nil {
		return types.Binding{}, err
	}
	if rb.Spec.Principal.Name == "" || rb.Spec.Role == "" {
		return types.Binding{}, fmt.Errorf("missing principal.name or role")
	}

	prefix := "User:"
	if strings.EqualFold(rb.Spec.Principal.Type, "group") {
		prefix = "Group:"
	}

	patterns := make([]types.ResourcePattern, 0, len(rb.Spec.ResourcePatterns))
	for _, p := range rb.Spec.ResourcePatterns {
		patterns = append(patterns, types.ResourcePattern{
			ResourceType: types.ResourceType(p.ResourceType),
			Name:         p.Name,
			PatternType:  types.PatternType(strings.ToUpper(p.PatternType)),
		})
	}

	return types.Binding{
		Action:    types.ActionCreate,
		Principal: prefix + rb.Spec.Principal.Name,
		Role:      rb.Spec.Role,
		Scope: types.Scope{
			KafkaCluster:          rb.Spec.ClustersScopeByIds.KafkaClusterID,
			SchemaRegistryCluster: rb.Spec.ClustersScopeByIds.SchemaRegistryClusterID,
			KSQLCluster:           rb.Spec.ClustersScopeByIds.KSQLClusterID,
			ConnectCluster:        rb.Spec.ClustersScopeByIds.ConnectClusterID,
		},
		ResourcePatterns: patterns,
	}, nil
}

func walkYAMLFiles(p string) ([]string, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{p}, nil
	}
	var files []string
	err = filepath.Walk(p, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

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
