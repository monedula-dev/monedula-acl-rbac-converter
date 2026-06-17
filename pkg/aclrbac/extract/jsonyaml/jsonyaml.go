// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package jsonyaml is the canonical-IR adapter: reads an acls.json or
// acls.yaml file matching schemas/acls.v1.json and emits it verbatim.
package jsonyaml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/schema"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// Adapter parses acls.json / acls.yaml files.
type Adapter struct {
	path string
}

// New builds an Adapter for the given file path. The file's extension
// determines whether to parse as JSON (.json) or YAML (.yaml / .yml).
func New(path string) (*Adapter, error) {
	return &Adapter{path: path}, nil
}

func (a *Adapter) Name() string { return "jsonyaml" }

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("read %s: %w", a.path, err)
	}

	jsonData := data
	if isYAMLFile(a.path) {
		jsonData, err = yamlToJSON(data)
		if err != nil {
			return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("convert yaml: %w", err)
		}
	}

	if err := schema.ValidateACLs(jsonData); err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("validate %s: %w", a.path, err)
	}

	var set types.ACLSet
	if err := json.Unmarshal(jsonData, &set); err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("decode %s: %w", a.path, err)
	}

	log.Logf("PARSED %d ACL row(s) from %s", len(set.ACLs), a.path)

	sum := sha256.Sum256(data)
	src := extract.ExtractSource{
		Kind:        formatFromExt(a.path),
		InputPath:   a.path,
		InputSHA256: hex.EncodeToString(sum[:]),
		Timestamp:   time.Now().UTC(),
	}
	return set, nil, src, log, nil
}

func isYAMLFile(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

func formatFromExt(p string) string {
	if isYAMLFile(p) {
		return "yaml"
	}
	return "json"
}

func yamlToJSON(in []byte) ([]byte, error) {
	var v interface{}
	if err := yaml.Unmarshal(in, &v); err != nil {
		return nil, err
	}
	v = convertMapInterface(v)
	return json.Marshal(v)
}

func convertMapInterface(v interface{}) interface{} {
	switch x := v.(type) {
	case map[interface{}]interface{}:
		m := map[string]interface{}{}
		for k, val := range x {
			m[fmt.Sprintf("%v", k)] = convertMapInterface(val)
		}
		return m
	case map[string]interface{}:
		for k, val := range x {
			x[k] = convertMapInterface(val)
		}
		return x
	case []interface{}:
		for i := range x {
			x[i] = convertMapInterface(x[i])
		}
		return x
	}
	return v
}
